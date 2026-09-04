from tempfile import TemporaryDirectory
import unittest

from agents import COMMUNICATION_LEXICON, CommunicationScanner, RegulatoryUpdateTracker, TransactionMonitor, resolve_conflicts, run_case, validate_scenarios
from review import latest_review, record_review
from report import generate_stakeholder_report, render_markdown, verify_audit_chain, write_markdown_report, write_report
from storage import ComplianceStore
from auth import authenticate, make_password_hash
from ingestion import load_json_events
from regulatory import assess_change
from feed_monitor import fetch_official_feed
from rules import SCENARIOS, calibrate_confidence


class CompliancePipelineTests(unittest.TestCase):
	def test_all_validation_scenarios_pass(self):
		reports = validate_scenarios(SCENARIOS)
		self.assertEqual(len(reports), 20)
		self.assertTrue(all(report["validation"] == "pass" for report in reports))


	def test_agent_handoff_has_trace_and_recipient(self):
		result = TransactionMonitor().run(SCENARIOS[0], "trace-test")
		self.assertEqual(result.trace_id, "trace-test")
		self.assertEqual(result.messages[0].recipient, "communication_scanner")
		self.assertNotIn("facts", result.messages[0].payload)
		self.assertEqual(result.messages[0].payload["case_id"], "CS-01")


	def test_regulatory_tracker_emits_assessment(self):
		result = RegulatoryUpdateTracker().run(next(item for item in SCENARIOS if item["case_id"] == "CS-07"), "trace-test")
		self.assertEqual(result.agent, "regulatory_update_tracker")
		self.assertEqual(result.findings[0].rule_id, "REGCHANGE-001")
		self.assertEqual(result.messages[0].message_type, "regulatory_assessment")


	def test_regulatory_change_assessment_requires_official_source(self):
		change = {"change_id": "REG-01", "source": "SEC", "title": "Margin update", "effective_date": "2027-01-01", "jurisdictions": ["US"], "domains": ["trading"]}
		assessment = assess_change(change)
		self.assertEqual(assessment.impact, "medium")
		with self.assertRaises(ValueError):
			assess_change({**change, "source": "blog"})


	def test_report_captures_all_four_agents(self):
		report = run_case(SCENARIOS[0])
		self.assertEqual(len(report["audit"]["agents"]), 4)
		self.assertEqual(report["audit"]["message_count"], 3)
		self.assertEqual(len(report["audit"]["messages"]), 3)
		self.assertEqual(report["audit"]["messages"][0]["sender"], "transaction_monitor")
		self.assertEqual([step["step"] for step in report["audit"]["trace_steps"]], ["intake", "signal_detection", "communication_assessment", "regulatory_assessment", "conflict_resolution", "report_generation"])


	def test_summary_contains_latency_percentiles(self):
		from report import summary
		result = summary(validate_scenarios(SCENARIOS))
		self.assertEqual(set(result["latency_percentiles_ms"]), {"transaction_monitor", "communication_scanner", "regulatory_update_tracker", "report_generator", "pipeline"})
		self.assertLessEqual(result["latency_percentiles_ms"]["pipeline"]["p50"], result["latency_percentiles_ms"]["pipeline"]["p99"])


	def test_agent_failure_fails_closed_to_human_review(self):
		from unittest.mock import patch
		with patch("agents.TransactionMonitor.run", side_effect=RuntimeError("timeout")):
			report = run_case(SCENARIOS[0])
		self.assertEqual(report["risk"], "critical")
		self.assertTrue(report["escalate"])
		self.assertIn("failed", report["audit"]["agent_status"]["transaction_monitor"])
		self.assertIn("timeout", report["audit"]["warnings"][0])


	def test_agent_rule_boundaries_prevent_cross_domain_findings(self):
		communication_case = next(item for item in SCENARIOS if item["case_id"] == "CS-13")
		transaction_result = TransactionMonitor().run(communication_case, "trace-test")
		communication_result = CommunicationScanner().run(communication_case, "trace-test")
		self.assertEqual(transaction_result.findings, [])
		self.assertTrue(any(item.rule_id == "COMMS-001" for item in communication_result.findings))


	def test_communication_lexicon_covers_required_languages(self):
		self.assertTrue(all(language in COMMUNICATION_LEXICON for language in ("en", "zh", "hi", "es")))
		for phrase in ("误导", "भ्रामक", "engañoso"):
			case = {**SCENARIOS[2], "facts": phrase}
			self.assertTrue(CommunicationScanner().run(case, "trace-test").messages)


	def test_conflict_resolution_keeps_highest_severity(self):
		low = run_case(SCENARIOS[0])["findings"][0].copy()
		low["severity"] = "medium"
		high = low.copy()
		high["severity"] = "critical"
		from agents import Finding
		resolved = resolve_conflicts([Finding(**low), Finding(**high)])
		self.assertEqual(len(resolved), 1)
		self.assertEqual(resolved[0].severity, "critical")
		self.assertEqual(resolved[0].status, "escalated_conflict")


	def test_finding_id_is_deterministic(self):
		first = run_case(SCENARIOS[0])
		second = run_case(SCENARIOS[0])
		self.assertEqual([item["finding_id"] for item in first["findings"]], [item["finding_id"] for item in second["findings"]])


	def test_confidence_calibration_is_bounded_and_reproducible(self):
		self.assertEqual(calibrate_confidence(0.92, "COMMS-001"), 0.7912)
		self.assertEqual(calibrate_confidence(2.0, "unknown-rule"), 1.0)
		self.assertEqual(calibrate_confidence(-1.0, "unknown-rule"), 0.0)
		self.assertIn("calibration_version", run_case(SCENARIOS[0])["audit"])


	def test_legitimate_block_trade_is_suppressed(self):
		report = run_case(next(item for item in SCENARIOS if item["case_id"] == "CS-18"))
		self.assertEqual(report["finding_count"], 0)
		self.assertFalse(report["escalate"])


	def test_review_requires_identity_and_rationale(self):
		report = run_case(SCENARIOS[0])
		with TemporaryDirectory() as folder:
			with self.assertRaises(ValueError):
				record_review(report, "", "compliance_officer", "approve", "", folder)
			record_review(report, "reviewer-1", "compliance_officer", "escalate", "Evidence requires senior review.", folder)
			event = latest_review(report["case_id"], folder)
			self.assertEqual(event["decision"], "escalate")
			self.assertEqual(event["reviewer_id"], "reviewer-1")


	def test_critical_approval_requires_elevated_role(self):
		report = run_case(SCENARIOS[0])
		with TemporaryDirectory() as folder:
			with self.assertRaises(ValueError):
				record_review(report, "reviewer-1", "compliance_officer", "approve", "Approved.", folder)
			record_review(report, "mlro-1", "mlro", "approve", "Critical evidence reviewed and disposition approved.", folder)


	def test_feed_monitor_rejects_unapproved_source(self):
		snapshot = fetch_official_feed("unknown")
		self.assertEqual(snapshot.status, "rejected")
		self.assertIn("allowlist", snapshot.error)


	def test_audit_chain_detects_tampering(self):
		report = run_case(SCENARIOS[0])
		with TemporaryDirectory() as folder:
			write_report(report, folder)
			self.assertEqual(verify_audit_chain(folder), (True, "verified"))
			from pathlib import Path
			audit_path = Path(folder) / "audit-events.jsonl"
			audit_path.write_text(audit_path.read_text(encoding="utf-8").replace("report_written", "tampered", 1), encoding="utf-8")
			verified, message = verify_audit_chain(folder)
			self.assertFalse(verified)
			self.assertIn("tamper detected", message)


	def test_markdown_report_contains_findings_and_audit_metadata(self):
		report = run_case(SCENARIOS[0])
		markdown = render_markdown(report)
		self.assertIn("# Compliance report: CS-01", markdown)
		self.assertIn("MNPI-001", markdown)
		self.assertIn("Scenario hash", markdown)
		with TemporaryDirectory() as folder:
			self.assertTrue(write_markdown_report(report, folder).exists())


	def test_stakeholder_report_profiles_filter_by_risk_and_fields(self):
		report = run_case(SCENARIOS[0])
		management = generate_stakeholder_report(report, "senior_management")
		self.assertEqual(management["profile"], "senior_management")
		self.assertNotIn("findings", management)
		auditor = generate_stakeholder_report(report, "external_auditor")
		self.assertIn("findings", auditor)
		with self.assertRaises(ValueError):
			generate_stakeholder_report(report, "unknown")


	def test_sqlite_store_persists_report_and_review(self):
		report = run_case(SCENARIOS[0])
		with TemporaryDirectory() as folder:
			write_report(report, folder)
			record_review(report, "reviewer-1", "compliance_officer", "escalate", "Needs senior review.", folder)
			store = ComplianceStore(folder + "/compliance.db")
			self.assertEqual(store.counts()["reports"], 1)
			self.assertEqual(store.counts()["runs"], 1)
			self.assertEqual(store.latest_review(report["case_id"])["decision"], "escalate")
			self.assertEqual(store.search_reports("CS-01")[0]["case_id"], "CS-01")


	def test_reviewer_authentication_uses_hashed_password(self):
		import os
		previous = os.environ.get("SENTINEL_USERS")
		os.environ["SENTINEL_USERS"] = '{"reviewer-1":{"role":"compliance_officer","password_hash":"' + make_password_hash("correct", "test-salt") + '"}}'
		try:
			self.assertEqual(authenticate("reviewer-1", "correct").role, "compliance_officer")
			self.assertIsNone(authenticate("reviewer-1", "wrong"))
		finally:
			if previous is None:
				os.environ.pop("SENTINEL_USERS", None)
			else:
				os.environ["SENTINEL_USERS"] = previous


	def test_json_ingestion_validates_and_quarantines_bad_events(self):
		valid = '{"case_id":"EXT-01","title":"External event","domain":"trading","jurisdiction":"SEC","facts":"Spoofing pattern detected","expected":"high","source":"internal feed"}'
		result = load_json_events("[" + valid + ", {\"case_id\":\"BAD\",\"domain\":\"unknown\"}]")
		self.assertEqual(len(result.scenarios), 1)
		self.assertEqual(len(result.errors), 1)
		self.assertIn("missing fields", result.errors[0])
