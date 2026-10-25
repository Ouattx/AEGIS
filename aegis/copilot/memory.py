"""Bounded, per-user conversation memory.

A session is keyed by ``(tenant_id, user_id, session_id)``: the same session id used by
another user or tenant is a different session, so memory never crosses those lines.
Only validated answers (with their citations) are remembered, never raw tool output.
Everything is bounded: turns per session, characters replayed to the model, refs
remembered, number of sessions (LRU) and idle lifetime.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable


@dataclass(frozen=True)
class MemoryTurn:
    question: str
    answer: str


@dataclass
class ConversationSession:
    tenant_id: str
    user_id: str
    session_id: str
    max_turns: int = 8
    max_refs: int = 4_000
    turns: deque[MemoryTurn] = field(default_factory=deque)
    seen: "OrderedDict[str, None]" = field(default_factory=OrderedDict)
    last_used: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def history_messages(self, max_chars: int = 12_000) -> list[dict[str, Any]]:
        """Most recent turns as alternating user/assistant text messages, within ``max_chars``."""
        picked: list[MemoryTurn] = []
        used = 0
        for t in reversed(self.turns):
            size = len(t.question) + len(t.answer)
            if used + size > max_chars:
                break
            picked.append(t)
            used += size
        out: list[dict[str, Any]] = []
        for t in reversed(picked):
            out.append({"role": "user", "content": t.question})
            out.append({"role": "assistant", "content": t.answer})
        return out

    def add_turn(self, question: str, answer: str) -> None:
        self.turns.append(MemoryTurn(question=question[:4_000], answer=answer[:8_000]))
        while len(self.turns) > self.max_turns:
            self.turns.popleft()

    def add_refs(self, refs: Iterable[str]) -> None:
        for r in refs:
            self.seen[r] = None
            self.seen.move_to_end(r)
        while len(self.seen) > self.max_refs:
            self.seen.popitem(last=False)

    def seen_refs(self) -> set[str]:
        return set(self.seen)


class SessionStore:
    """Thread-safe LRU of conversation sessions."""

    def __init__(self, *, max_sessions: int = 1_000, max_turns: int = 8, max_refs: int = 4_000,
                 idle_ttl_s: float = 3_600.0, monotonic: Callable[[], float] = time.monotonic):
        if max_sessions < 1 or max_turns < 0 or max_refs < 1 or idle_ttl_s <= 0:
            raise ValueError("invalid session store bounds")
        self._max_sessions = max_sessions
        self._max_turns = max_turns
        self._max_refs = max_refs
        self._ttl = idle_ttl_s
        self._mono = monotonic
        self._sessions: OrderedDict[tuple[str, str, str], ConversationSession] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, tenant_id: str, user_id: str, session_id: str) -> ConversationSession:
        key = (tenant_id, user_id, session_id)
        now = self._mono()
        with self._lock:
            self._expire(now)
            s = self._sessions.get(key)
            if s is None:
                s = ConversationSession(tenant_id=tenant_id, user_id=user_id, session_id=session_id,
                                        max_turns=self._max_turns, max_refs=self._max_refs)
                self._sessions[key] = s
            self._sessions.move_to_end(key)
            s.last_used = now
            while len(self._sessions) > self._max_sessions:
                self._sessions.popitem(last=False)
            return s

    def drop(self, tenant_id: str, user_id: str, session_id: str) -> bool:
        with self._lock:
            return self._sessions.pop((tenant_id, user_id, session_id), None) is not None

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)

    def _expire(self, now: float) -> None:
        stale = [k for k, s in self._sessions.items() if now - s.last_used > self._ttl]
        for k in stale:
            del self._sessions[k]
