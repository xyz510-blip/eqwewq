"""SQLite persistence layer for investigation cases and scammer watchlist."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from opensearch_lab.core.models import InvestigationReport, utc_now_iso


class Storage:
    """Thread-safe SQLite storage for investigation dossiers and local scam watchlist."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), timeout=15)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    query TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    risk_level TEXT NOT NULL DEFAULT 'LOW',
                    created_at TEXT NOT NULL,
                    notes TEXT NOT NULL DEFAULT '',
                    report_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_query ON cases(query)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cases_created ON cases(created_at DESC)"
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS watchlist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT NOT NULL UNIQUE,
                    indicator_type TEXT NOT NULL DEFAULT 'unknown',
                    label TEXT NOT NULL DEFAULT 'Suspected Scammer',
                    reason TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT 'manual',
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def save_case(self, report: InvestigationReport) -> None:
        """Persist or overwrite an InvestigationReport."""
        payload = json.dumps(report.to_dict(), ensure_ascii=False)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO cases (case_id, query, target_type, risk_score, risk_level, created_at, notes, report_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(case_id) DO UPDATE SET
                    query = excluded.query,
                    target_type = excluded.target_type,
                    risk_score = excluded.risk_score,
                    risk_level = excluded.risk_level,
                    notes = excluded.notes,
                    report_json = excluded.report_json
                """,
                (
                    report.case_id,
                    report.query,
                    report.target_type.value,
                    report.risk.score,
                    report.risk.level,
                    report.created_at,
                    report.notes,
                    payload,
                ),
            )
            conn.commit()

    def get_case(self, case_id: str) -> InvestigationReport | None:
        """Load an InvestigationReport by case_id (supports prefix match)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT report_json FROM cases WHERE case_id = ?", (case_id,)
            ).fetchone()
            if row is None:
                row = conn.execute(
                    "SELECT report_json FROM cases WHERE case_id LIKE ? ORDER BY created_at DESC LIMIT 1",
                    (f"{case_id}%",),
                ).fetchone()
        if row is None:
            return None
        return InvestigationReport.from_dict(json.loads(row["report_json"]))

    def list_cases(self, limit: int = 30, search: str = "") -> list[dict[str, Any]]:
        """List saved investigation summaries ordered by newest first."""
        with self._connect() as conn:
            if search.strip():
                like = f"%{search.strip()}%"
                rows = conn.execute(
                    """
                    SELECT case_id, query, target_type, risk_score, risk_level, created_at, notes
                    FROM cases
                    WHERE query LIKE ? OR notes LIKE ? OR case_id LIKE ?
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (like, like, like, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT case_id, query, target_type, risk_score, risk_level, created_at, notes
                    FROM cases
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        return [dict(r) for r in rows]

    def search_cases(self, keyword: str, limit: int = 30) -> list[dict[str, Any]]:
        """Search cases by query, notes, or case_id."""
        return self.list_cases(limit=limit, search=keyword)

    def update_case_notes(self, case_id: str, notes: str) -> bool:
        """Update investigator notes on a saved case."""
        report = self.get_case(case_id)
        if report is None:
            return False
        report.notes = notes
        self.save_case(report)
        return True

    def delete_case(self, case_id: str) -> bool:
        """Delete a case by exact case_id."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))
            conn.commit()
            return cur.rowcount > 0

    def add_watchlist(
        self,
        indicator: str,
        indicator_type: str = "unknown",
        label: str = "Suspected Scammer",
        reason: str = "",
        source: str = "manual",
    ) -> int:
        """Insert or update an indicator in the local scammer watchlist."""
        normalized = indicator.strip().lower()
        if not normalized:
            raise ValueError("Indicator cannot be empty")
        now = utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO watchlist (indicator, indicator_type, label, reason, source, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(indicator) DO UPDATE SET
                    indicator_type = excluded.indicator_type,
                    label = excluded.label,
                    reason = excluded.reason,
                    source = excluded.source
                """,
                (normalized, indicator_type, label, reason, source, now),
            )
            row = conn.execute(
                "SELECT id FROM watchlist WHERE indicator = ?", (normalized,)
            ).fetchone()
            conn.commit()
            return int(row["id"]) if row else 0

    def remove_watchlist(self, entry_id: int) -> bool:
        """Remove a watchlist entry by numeric ID."""
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM watchlist WHERE id = ?", (entry_id,))
            conn.commit()
            return cur.rowcount > 0

    def list_watchlist(self, limit: int = 200) -> list[dict[str, Any]]:
        """List watchlist entries ordered by newest first."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, indicator, indicator_type, label, reason, source, created_at
                FROM watchlist
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def match_watchlist(
        self,
        indicators: list[str],
        exclude_case_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Match normalized indicators against watchlist AND prior investigation cases."""
        cleaned = sorted({i.strip().lower() for i in indicators if i and i.strip()})
        if not cleaned:
            return []

        matches: list[dict[str, Any]] = []
        with self._connect() as conn:
            placeholders = ",".join("?" for _ in cleaned)
            w_rows = conn.execute(
                f"""
                SELECT id, indicator, indicator_type, label, reason, source, created_at
                FROM watchlist
                WHERE indicator IN ({placeholders})
                """,
                cleaned,
            ).fetchall()
            for r in w_rows:
                item = dict(r)
                item["match_kind"] = "watchlist"
                matches.append(item)

            # Also check prior cases where query or entity values overlap
            c_rows = conn.execute(
                """
                SELECT case_id, query, target_type, risk_score, risk_level, created_at, report_json
                FROM cases
                ORDER BY created_at DESC
                LIMIT 100
                """
            ).fetchall()
            indicator_set = set(cleaned)
            seen_cases: set[str] = set()
            for row in c_rows:
                cid = str(row["case_id"])
                if exclude_case_id and cid == exclude_case_id:
                    continue
                q_lower = str(row["query"]).strip().lower()
                matched_val = ""
                if q_lower in indicator_set:
                    matched_val = q_lower
                else:
                    try:
                        raw_report = json.loads(row["report_json"])
                        for ent in raw_report.get("entities") or []:
                            lbl = str(ent.get("label", "")).strip().lower()
                            if lbl in indicator_set and len(lbl) >= 4:
                                matched_val = lbl
                                break
                    except Exception:
                        matched_val = ""

                if matched_val and cid not in seen_cases:
                    seen_cases.add(cid)
                    matches.append(
                        {
                            "match_kind": "prior_case",
                            "case_id": cid,
                            "indicator": matched_val,
                            "prior_query": row["query"],
                            "risk_score": row["risk_score"],
                            "risk_level": row["risk_level"],
                            "created_at": row["created_at"],
                        }
                    )

        return matches
