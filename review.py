"""Human-in-the-loop decisions with append-only audit persistence."""

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from report import _append_audit_event
from storage import ComplianceStore


ALLOWED_DECISIONS = {"approve", "reject", "escalate"}
REVIEW_ROLES = {"compliance_officer", "senior_compliance_officer", "mlro"}


@dataclass(frozen=True)
class ReviewDecision:
	case_id: str
	trace_id: str
	reviewer_id: str
	reviewer_role: str
	decision: str
	rationale: str
	previous_status: str
	created_at: str


def record_review(report: dict[str, Any], reviewer_id: str, reviewer_role: str, decision: str, rationale: str, output_dir: str = "reports") -> ReviewDecision:
	if reviewer_role not in REVIEW_ROLES:
		raise ValueError("Reviewer role is not authorized for compliance decisions")
	if decision not in ALLOWED_DECISIONS:
		raise ValueError("Decision must be approve, reject, or escalate")
	if not reviewer_id.strip() or not rationale.strip():
		raise ValueError("Reviewer identity and rationale are required")
	if report.get("risk") == "critical" and decision == "approve" and reviewer_role not in {"senior_compliance_officer", "mlro"}:
		raise ValueError("Critical findings require senior compliance officer or MLRO approval")
	previous_status = "pending_review" if report.get("escalate") else "open"
	created_at = datetime.now(timezone.utc).isoformat()
	review = ReviewDecision(report["case_id"], report["trace_id"], reviewer_id.strip(), reviewer_role, decision, rationale.strip(), previous_status, created_at)
	path = Path(output_dir)
	path.mkdir(parents=True, exist_ok=True)
	with (path / "review-events.jsonl").open("a", encoding="utf-8") as stream:
		stream.write(json.dumps(asdict(review), sort_keys=True) + "\n")
	payload_hash = sha256(json.dumps(asdict(review), sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
	event = _append_audit_event({"event_type": "review_recorded", "case_id": review.case_id, "trace_id": review.trace_id, "actor": review.reviewer_id, "payload_hash": payload_hash}, path)
	store = ComplianceStore(str(path / "compliance.db"))
	store.save_audit_event(event)
	store.save_review(asdict(review))
	return review


def latest_review(case_id: str, output_dir: str = "reports") -> dict[str, Any] | None:
	file_path = Path(output_dir) / "review-events.jsonl"
	if not file_path.exists():
		return None
	latest = None
	for line in file_path.read_text(encoding="utf-8").splitlines():
		if line.strip():
			event = json.loads(line)
			if event["case_id"] == case_id:
				latest = event
	return latest
