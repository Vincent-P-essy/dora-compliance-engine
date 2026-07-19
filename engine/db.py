"""Database layer: SQLAlchemy models and session management.

Timestamps are stored as naive UTC datetimes so behavior is identical across
PostgreSQL (production) and SQLite (tests). The Evidence Vault's append-only
guarantee is enforced twice: here at the ORM level (any UPDATE/DELETE on an
:class:`EvidenceRecord` raises), and in PostgreSQL by a trigger created in
``sql/init.sql``.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, Integer, String, create_engine, event
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    scoped_session,
    sessionmaker,
)


def utcnow() -> datetime:
    """Naive UTC now — the single timestamp convention for all models."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False)  # CISO | DevOps | Auditor
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class EvidenceRecord(Base):
    """One immutable, hashed piece of audit evidence."""

    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    control_ids: Mapped[list] = mapped_column(JSON, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    collected_at: Mapped[str] = mapped_column(String(40), nullable=False)
    stored_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class PostureSnapshot(Base):
    """Score of one framework at one point in time (history for drift)."""

    __tablename__ = "posture_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    passed: Mapped[int] = mapped_column(Integer, nullable=False)
    total: Mapped[int] = mapped_column(Integer, nullable=False)
    results: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)


class DriftAlert(Base):
    __tablename__ = "drift_alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework: Mapped[str] = mapped_column(String(32), nullable=False)
    baseline_score: Mapped[float] = mapped_column(Float, nullable=False)
    current_score: Mapped[float] = mapped_column(Float, nullable=False)
    delta: Mapped[float] = mapped_column(Float, nullable=False)
    message: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class ImmutableEvidenceError(RuntimeError):
    """Raised on any attempt to update or delete stored evidence."""


@event.listens_for(Session, "before_flush")
def _forbid_evidence_mutation(session, flush_context, instances) -> None:
    for obj in session.dirty:
        if isinstance(obj, EvidenceRecord) and session.is_modified(obj):
            raise ImmutableEvidenceError(
                "Evidence vault is append-only: UPDATE is forbidden"
            )
    for obj in session.deleted:
        if isinstance(obj, EvidenceRecord):
            raise ImmutableEvidenceError(
                "Evidence vault is append-only: DELETE is forbidden"
            )


SessionLocal = scoped_session(sessionmaker(expire_on_commit=False))
_engine = None


def init_engine(database_url: str | None = None):
    """Bind the global session factory to a database. Returns the engine."""
    global _engine
    url = database_url or os.environ.get("DATABASE_URL", "sqlite:///dora.db")
    kwargs: dict = {"future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
    _engine = create_engine(url, **kwargs)
    SessionLocal.remove()
    SessionLocal.configure(bind=_engine)
    return _engine


def init_db() -> None:
    """Create all tables (idempotent; PostgreSQL is pre-created by sql/init.sql)."""
    if _engine is None:
        raise RuntimeError("init_engine() must be called before init_db()")
    Base.metadata.create_all(_engine)
