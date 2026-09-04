"""SQLite persistence for searchable reports, audit events, and review decisions."""

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any


class ComplianceStore:
	def __init__(self, database_path: str = "reports/compliance.db") -> None:
		self.database_path = Path(database_path)
		self.database_path.parent.mkdir(parents=True, exist_ok=True)
		self._initialize()

	@contextmanager
	def _connect(self):
		connection = sqlite3.connect(self.database_path)
		connection.row_factory = sqlite3.Row
		try:
			yield connection
		except Exception:
			connection.rollback()
			raise
		else:
			connection.commit()
		finally:
			connection.close()

	def _initialize(self) -> None:
		with self._connect() as connection:
			connection.executescript("""
			CREATE TABLE IF NOT EXISTS reports (
				trace_id TEXT PRIMARY KEY,
				case_id TEXT NOT NULL,
				risk TEXT NOT NULL,
				escalate INTEGER NOT NULL,
				created_at TEXT NOT NULL,
				payload TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS audit_events (
				sequence INTEGER PRIMARY KEY AUTOINCREMENT,
				event_hash TEXT UNIQUE NOT NULL,
				previous_hash TEXT NOT NULL,
				event_type TEXT NOT NULL,
				case_id TEXT NOT NULL,
				trace_id TEXT NOT NULL,
				actor TEXT NOT NULL,
				payload_hash TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS review_decisions (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				case_id TEXT NOT NULL,
				trace_id TEXT NOT NULL,
				reviewer_id TEXT NOT NULL,
				reviewer_role TEXT NOT NULL,
				decision TEXT NOT NULL,
				rationale TEXT NOT NULL,
				created_at TEXT NOT NULL
			);
			""")

	def save_report(self, report: dict[str, Any]) -> None:
		with self._connect() as connection:
			connection.execute("INSERT OR REPLACE INTO reports VALUES (?, ?, ?, ?, ?, ?)", (report["trace_id"], report["case_id"], report["risk"], int(report["escalate"]), report["audit"]["created_at"], json.dumps(report, sort_keys=True)))

	def save_audit_event(self, event: dict[str, Any]) -> None:
		with self._connect() as connection:
			connection.execute("INSERT OR IGNORE INTO audit_events (event_hash, previous_hash, event_type, case_id, trace_id, actor, payload_hash) VALUES (?, ?, ?, ?, ?, ?, ?)", (event["event_hash"], event["previous_hash"], event["event_type"], event["case_id"], event["trace_id"], event["actor"], event["payload_hash"]))

	def save_review(self, review: dict[str, Any]) -> None:
		with self._connect() as connection:
			connection.execute("INSERT INTO review_decisions (case_id, trace_id, reviewer_id, reviewer_role, decision, rationale, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", tuple(review[key] for key in ("case_id", "trace_id", "reviewer_id", "reviewer_role", "decision", "rationale", "created_at")))

	def latest_review(self, case_id: str) -> dict[str, Any] | None:
		with self._connect() as connection:
			row = connection.execute("SELECT * FROM review_decisions WHERE case_id = ? ORDER BY id DESC LIMIT 1", (case_id,)).fetchone()
		return dict(row) if row else None

	def counts(self) -> dict[str, int]:
		with self._connect() as connection:
			row = connection.execute("SELECT COUNT(DISTINCT case_id) AS reports, COUNT(*) AS runs, COALESCE(SUM(escalate), 0) AS escalations FROM reports").fetchone()
		return {"reports": row["reports"], "runs": row["runs"], "escalations": row["escalations"]}

	def search_reports(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
		term = f"%{query.strip()}%"
		with self._connect() as connection:
			rows = connection.execute("SELECT case_id, trace_id, risk, escalate, created_at FROM reports WHERE case_id LIKE ? OR trace_id LIKE ? OR risk LIKE ? ORDER BY created_at DESC LIMIT ?", (term, term, term, limit)).fetchall()
		return [dict(row) for row in rows]
