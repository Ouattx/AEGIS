"""Two-party private set intersection (Diffie-Hellman / commutative-exponentiation PSI).

Use when two consortium members want to learn which indicators they *both* hold
without trusting each other with a shared HMAC key (with a shared key, a dishonest
member can test guesses offline; see :mod:`aegis.intel.sharing`). Protocol
(Meadows 1986; Huberman, Franklin & Hogg 1999), semi-honest model, in the
2048-bit MODP group of RFC 3526 (group 14, safe prime ``p = 2q + 1``)::

    A: X_A = { H(x)^a : x in A }             --->  B
    B: Y   = { (H(x)^a)^b } (same order as X_A),  X_B = shuffle{ H(y)^b : y in B }  ---> A
    A: Z   = { (H(y)^b)^a } ;  A ∩ B = { x_i : Y_i ∈ Z }

``H`` hashes ``type|value`` to the order-q subgroup of quadratic residues (squaring
an expanded SHA-256 digest), so DDH holds and nothing but the intersection (and the
other side's set *size*) is revealed to A; B learns only A's set size. Received group
elements are validated to lie in the subgroup (no small-subgroup confinement).

Limitations: semi-honest only (a malicious party can put guesses into its own set;
cap set sizes with ``max_items``); about 2-4 ms per exponentiation in pure Python, so
it suits sets of up to tens of thousands of indicators per run, not full feeds.
"""
from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterable, Sequence

# RFC 3526, 2048-bit MODP group (id 14)
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
Q = (P - 1) // 2
_ELEM_HEX = (P.bit_length() + 7) // 8 * 2


class PSIError(ValueError):
    pass


def hash_to_group(typ: str, value: str) -> int:
    """Map a normalized indicator to the quadratic-residue subgroup of order Q."""
    seed = f"aegis-psi-v1|{typ}|{value}".encode()
    stream = b"".join(hashlib.sha256(seed + i.to_bytes(4, "big")).digest() for i in range(9))
    x = int.from_bytes(stream, "big") % P
    if x in (0, 1, P - 1):           # negligible; keep the map total
        x = 2
    return pow(x, 2, P)


def _encode(e: int) -> str:
    return format(e, f"0{_ELEM_HEX}x")


def _decode(s: str) -> int:
    if not isinstance(s, str) or len(s) != _ELEM_HEX:
        raise PSIError("malformed group element")
    try:
        e = int(s, 16)
    except ValueError as exc:
        raise PSIError("malformed group element") from exc
    if not 1 < e < P - 1 or pow(e, Q, P) != 1:
        raise PSIError("element is not in the prime-order subgroup")
    return e


class PSIParty:
    """One side of the protocol, holding a secret exponent and its own (normalized) items."""

    def __init__(self, items: Iterable[tuple[str, str]], *, max_items: int = 50_000):
        self._items = sorted(set(items))
        if len(self._items) > max_items:
            raise PSIError(f"set larger than max_items={max_items}")
        self._max = max_items
        self._secret = 1 + secrets.randbelow(Q - 1)
        self._hashed = [hash_to_group(t, v) for t, v in self._items]

    @property
    def size(self) -> int:
        return len(self._items)

    # step 1 (initiator A)
    def blinded(self) -> list[str]:
        """``H(x)^secret`` for own items, in a fixed order (needed to map the answer back)."""
        return [_encode(pow(h, self._secret, P)) for h in self._hashed]

    # step 2 (responder B)
    def respond(self, their_blinded: Sequence[str]) -> tuple[list[str], list[str]]:
        """Return ``(their items re-blinded, in order, own items blinded, shuffled)``."""
        if len(their_blinded) > self._max:
            raise PSIError(f"peer set larger than max_items={self._max}")
        reblinded = [_encode(pow(_decode(e), self._secret, P)) for e in their_blinded]
        mine = self.blinded()
        secrets.SystemRandom().shuffle(mine)
        return reblinded, mine

    # step 3 (initiator A)
    def intersect(self, reblinded_mine: Sequence[str], their_blinded: Sequence[str]) -> list[tuple[str, str]]:
        """Own items that the peer also holds."""
        if len(reblinded_mine) != len(self._items):
            raise PSIError("response does not match the number of items sent")
        if len(their_blinded) > self._max:
            raise PSIError(f"peer set larger than max_items={self._max}")
        double_theirs = {pow(_decode(e), self._secret, P) for e in their_blinded}
        return [item for item, e in zip(self._items, reblinded_mine) if _decode(e) in double_theirs]


__all__ = ["P", "PSIError", "PSIParty", "Q", "hash_to_group"]
