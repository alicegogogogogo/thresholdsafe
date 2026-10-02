from __future__ import annotations

import json
import sqlite3
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


class CommitBeforeReraise(Exception):
    """Control-flow signal: commit the open transaction, then raise ``error``.

    A rejected write may still have to persist an audit event. The service
    appends the event inside the transaction and raises this marker so the
    transaction context commits the event instead of rolling it back, while
    callers still observe the original business error.
    """

    def __init__(self, error: BaseException):
        super().__init__(str(error))
        self.error = error


class Store:
    def __init__(self, path: str):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self.connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self.connection
        except CommitBeforeReraise as signal:
            self.connection.execute("COMMIT")
            raise signal.error from None
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        else:
            self.connection.execute("COMMIT")

    @staticmethod
    def encode(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)

    @staticmethod
    def decode(value: str) -> Any:
        return json.loads(value)

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
