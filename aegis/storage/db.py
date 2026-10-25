"""Shared storage: one SQLAlchemy engine, PostgreSQL in production, SQLite in tests.

Modules that need their own tables (provenance ledger, atlas graph) declare them on
``Base`` from this module so ``init_db`` creates everything in one place.
Generic contract objects (findings, cases, actions, policies...) live in DocStore.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Iterator, Type, TypeVar

from pydantic import BaseModel
from sqlalchemy import JSON, DateTime, Index, String, create_engine, select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class DocRow(Base):
    __tablename__ = "docs"
    kind: Mapped[str] = mapped_column(String(64), primary_key=True)
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    body: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (Index("ix_docs_kind_tenant", "kind", "tenant_id"),)


def make_engine(url: str | None = None) -> Engine:
    url = url or os.environ.get("AEGIS_DATABASE_URL", "sqlite:///./aegis.db")
    kwargs = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    return create_engine(url, **kwargs)


def init_db(engine: Engine) -> None:
    # import modules that register tables on Base
    import aegis.provenance.ledger  # noqa: F401
    import aegis.atlas.graph  # noqa: F401
    Base.metadata.create_all(engine)


def make_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(engine, expire_on_commit=False, future=True)


M = TypeVar("M", bound=BaseModel)

# A model's own id comes first; ``case_id`` is last because several models
# (ProposedAction, investigation reports) also carry the case they belong to.
# ``doc_id`` is a generic key for configuration records (sources, IOC bundles, topology...).
_ID_FIELDS = ("finding_id", "evidence_id", "action_id", "policy_id", "event_id", "doc_id", "case_id")


def _id_of(obj: BaseModel) -> str:
    for f in _ID_FIELDS:
        if hasattr(obj, f):
            return getattr(obj, f)
    raise ValueError(f"no id field on {type(obj).__name__}")


class DocStore:
    """Tenant-scoped JSON document store for contract models.

    Every read requires a tenant_id: there is no cross-tenant query API.
    """

    def __init__(self, session_factory: sessionmaker[Session]):
        self._sf = session_factory

    def put(self, obj: BaseModel) -> None:
        kind = type(obj).__name__
        with self._sf.begin() as s:
            s.merge(DocRow(kind=kind, id=_id_of(obj), tenant_id=obj.tenant_id,
                           updated_at=datetime.now(timezone.utc),
                           body=obj.model_dump(mode="json")))

    def get(self, model: Type[M], tenant_id: str, id_: str) -> M | None:
        with self._sf() as s:
            row = s.get(DocRow, (model.__name__, id_))
            if row is None or row.tenant_id != tenant_id:
                return None
            return model.model_validate(row.body)

    def list(self, model: Type[M], tenant_id: str, limit: int = 1000) -> list[M]:
        with self._sf() as s:
            rows = s.scalars(select(DocRow).where(DocRow.kind == model.__name__,
                                                  DocRow.tenant_id == tenant_id)
                             .order_by(DocRow.updated_at.desc()).limit(limit))
            return [model.model_validate(r.body) for r in rows]

    def iter_all(self, model: Type[M], tenant_id: str) -> Iterator[M]:
        yield from self.list(model, tenant_id, limit=10_000_000)
