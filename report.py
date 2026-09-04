"""Audit-grade report serialization and persistence."""

import json
from hashlib import sha256
from pathlib import Path
from typing import Any

from storage import ComplianceStore


REPORT_PROFILES = {
	"compliance_committee": {"minimum_risk": "medium", "include_findings": True, "include_trace": True},
	"senior_management": {"minimum_risk": "high", "include_findings": False, "include_trace": False},
	"external_auditor": {"minimum_risk": "low", "include_findings": True, "include_trace": True},
	"regulator": {"minimum_risk": "low", "include_findings": True, "include_trace": True},
}


def generate_stakeholder_report(report: dict[str, Any], profile: str) -> dict[str, Any]:
	if profile not in REPORT_PROFILES:
		raise ValueError(f"Unknown report profile: {profile}")
	configuration = REPORT_PROFILES[profile]
	risk_rank = {"no_alert": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	if risk_rank.get(report["risk"], 0) < risk_rank[configuration["minimum_risk"]]:
		return {"profile": profile, "case_id": report["case_id"], "included": False, "reason": "below profile risk threshold"}
	output = {"profile": profile, "case_id": report["case_id"], "risk": report["risk"], "escalate": report["escalate"], "recommended_action": report["recommended_action"], "trace_id": report["trace_id"]}
	if configuration["include_findings"]:
		output["findings"] = report["findings"]
	if configuration["include_trace"]:
		output["audit"] = report["audit"]
	return output


def _canonical(value: dict[str, Any]) -> str:
	return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _last_hash(event_path: Path) -> str:
	if not event_path.exists():
		return "0" * 64
	lines = [line for line in event_path.read_text(encoding="utf-8").splitlines() if line.strip()]
	return json.loads(lines[-1])["event_hash"] if lines else "0" * 64


def _append_audit_event(event: dict[str, Any], output_dir: Path) -> dict[str, Any]:
	event_path = output_dir / "audit-events.jsonl"
	event["previous_hash"] = _last_hash(event_path)
	event["event_hash"] = sha256(_canonical(event).encode("utf-8")).hexdigest()
	with event_path.open("a", encoding="utf-8") as stream:
		stream.write(_canonical(event) + "\n")
	return event


def write_report(report: dict[str, Any], output_dir: str = "reports") -> Path:
	destination = Path(output_dir)
	destination.mkdir(parents=True, exist_ok=True)
	event = _append_audit_event({"event_type": "report_written", "case_id": report["case_id"], "trace_id": report["trace_id"], "actor": "report_generator", "payload_hash": sha256(_canonical(report).encode("utf-8")).hexdigest()}, destination)
	report["audit"]["event_hash"] = event["event_hash"]
	store = ComplianceStore(str(destination / "compliance.db"))
	store.save_audit_event(event)
	store.save_report(report)
	path = destination / f"{report['case_id']}-{report['trace_id']}.json"
	path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
	return path


def render_markdown(report: dict[str, Any]) -> str:
	lines = [
		f"# Compliance report: {report['case_id']}",
		f"- Risk: **{report['risk'].upper()}**",
		f"- Human escalation: **{'required' if report['escalate'] else 'not required'}**",
		f"- Recommended action: {report['recommended_action']}",
		f"- Trace ID: `{report['trace_id']}`",
		"",
		"## Findings",
	]
	if not report["findings"]:
		lines.append("No alert findings. The case passed the available verification controls.")
	else:
		for finding in report["findings"]:
			lines.extend([f"### {finding['rule_id']} ({finding['severity'].upper()})", finding["rationale"], f"- Confidence: {finding['confidence']}", f"- Citation: {finding['citation']}", ""])
	lines.extend(["## Audit metadata", f"- Rule version: `{report['audit']['rule_version']}`", f"- Calibration version: `{report['audit'].get('calibration_version', 'not recorded')}`", f"- Scenario hash: `{report['audit']['scenario_hash']}`", f"- Agents: {', '.join(report['audit']['agents'])}", f"- Pipeline latency: {report['audit'].get('latency_ms', {}).get('pipeline', 0)} ms"])
	lines.append("\n## Inter-agent messages")
	for message in report["audit"].get("messages", []):
		lines.append(f"- `{message['sender']}` -> `{message['recipient']}`: `{message['message_type']}` ({message['timestamp']})")
	return "\n".join(lines) + "\n"


def write_markdown_report(report: dict[str, Any], output_dir: str = "reports") -> Path:
	destination = Path(output_dir)
	destination.mkdir(parents=True, exist_ok=True)
	path = destination / f"{report['case_id']}-{report['trace_id']}.md"
	path.write_text(render_markdown(report), encoding="utf-8")
	return path


def summary(reports: list[dict[str, Any]]) -> dict[str, Any]:
	def percentile(values: list[float], fraction: float) -> float:
		if not values:
			return 0.0
		ordered = sorted(values)
		index = min(len(ordered) - 1, int(round((len(ordered) - 1) * fraction)))
		return round(ordered[index], 3)

	latency = {}
	for agent in ("transaction_monitor", "communication_scanner", "regulatory_update_tracker", "report_generator", "pipeline"):
		values = [item.get("audit", {}).get("latency_ms", {}).get(agent, 0.0) for item in reports]
		latency[agent] = {"p50": percentile(values, 0.50), "p95": percentile(values, 0.95), "p99": percentile(values, 0.99)}
	return {"cases": len(reports), "validation_passed": sum(item.get("validation") == "pass" for item in reports), "validation_failed": sum(item.get("validation") == "fail" for item in reports), "escalations": sum(item["escalate"] for item in reports), "critical": sum(item["risk"] == "critical" for item in reports), "high": sum(item["risk"] == "high" for item in reports), "rule_versions": sorted({item["audit"]["rule_version"] for item in reports}), "latency_percentiles_ms": latency}


def verify_audit_chain(output_dir: str = "reports") -> tuple[bool, str]:
	event_path = Path(output_dir) / "audit-events.jsonl"
	previous_hash = "0" * 64
	if not event_path.exists():
		return True, "empty"
	for line_number, line in enumerate(event_path.read_text(encoding="utf-8").splitlines(), start=1):
		if not line.strip():
			continue
		event = json.loads(line)
		claimed_hash = event.pop("event_hash", None)
		if event.get("previous_hash") != previous_hash or sha256(_canonical(event).encode("utf-8")).hexdigest() != claimed_hash:
			return False, f"tamper detected at event {line_number}"
		previous_hash = claimed_hash
	return True, "verified"
