from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  document TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS shares (
  share_id TEXT PRIMARY KEY,
  secret_id TEXT NOT NULL REFERENCES secrets(id),
  version INTEGER NOT NULL,
  holder TEXT NOT NULL,
  coordinate INTEGER NOT NULL,
  value TEXT NOT NULL,
  commitment TEXT NOT NULL,
  distributed_at TEXT,
  invalidated_at TEXT,
  UNIQUE (secret_id, version, holder)
);
CREATE TABLE IF NOT EXISTS approvals (
  secret_id TEXT NOT NULL REFERENCES secrets(id),
  version INTEGER NOT NULL,
  approver TEXT NOT NULL,
  created_at TEXT NOT NULL,
  consumed_at TEXT,
  PRIMARY KEY (secret_id, version, approver)
);
CREATE TABLE IF NOT EXISTS audit_events (
  secret_id TEXT NOT NULL REFERENCES secrets(id),
  sequence INTEGER NOT NULL,
  type TEXT NOT NULL,
  payload TEXT NOT NULL,
  occurred_at TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  PRIMARY KEY (secret_id, sequence)
);
CREATE TABLE IF NOT EXISTS idempotency (
  key TEXT PRIMARY KEY,
  operation TEXT NOT NULL,
  response TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._local = threading.local()
        # Create the schema eagerly so the file is fully initialised even when
        # worker threads later open their own connections.
        self._open()

    def _open(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.executescript(SCHEMA)
        self._local.connection = connection
        return connection

    @property
    def connection(self) -> sqlite3.Connection:
        connection = getattr(self._local, "connection", None)
        if connection is None:
            connection = self._open()
        return connection

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connection
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except Exception:
            connection.execute("ROLLBACK")
            raise
        else:
            connection.execute("COMMIT")

    @staticmethod
    def encode(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def decode(value: str) -> Any:
        return json.loads(value)

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
