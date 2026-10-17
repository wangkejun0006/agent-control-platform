"""Database lifecycle without implicit schema creation."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Database:
    def __init__(self, database_url: str, *, echo: bool = False) -> None:
        options = {
            "echo": echo,
            "future": True,
            "pool_pre_ping": True,
        }
        if database_url.startswith("sqlite"):
            options["connect_args"] = {"check_same_thread": False}
            if database_url.endswith(":memory:"):
                options["poolclass"] = StaticPool
        else:
            options["isolation_level"] = "SERIALIZABLE"
        self.engine: Engine = create_engine(database_url, **options)
        self._sessions = sessionmaker(
            bind=self.engine,
            class_=Session,
            expire_on_commit=False,
        )

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self._sessions.begin() as session:
            yield session

    def ping(self) -> bool:
        try:
            with self.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return True
        except Exception:  # noqa: BLE001 - health gate converts all DB failures to false
            return False

    def dispose(self) -> None:
        self.engine.dispose()

