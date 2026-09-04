"""Four bounded agents and their deterministic collaboration protocol."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from time import perf_counter
from typing import Any
from uuid import uuid4

from rules import (
    CALIBRATION_VERSION,
    RULE_VERSION,
    RuleDecision,
    calibrate_confidence,
    evaluate_rules,
)
from regulatory import assess_change


# ============================================================
# COMMUNICATION LEXICON
# ============================================================

COMMUNICATION_LEXICON = {
    "en": (
        "whatsapp",
        "misleading",
        "false",
        "delete",
        "promotion",
        "research",
        "communication",
        "guaranteed",
        "zero risk",
        "insider",
        "inside information",
        "guaranteed return",
        "guaranteed returns",
        "risk free",
        "risk-free",
    ),
    "hi": (
        "भ्रामक",
        "झूठा",
        "गारंटीड रिटर्न",
        "अंदरूनी जानकारी",
        "संदेश हटाएं",
        "जोखिम मुक्त",
        "बिना जोखिम",
    ),
    "mr": (
        "भ्रामक",
        "खोटी माहिती",
        "हमीचा परतावा",
        "आतील माहिती",
        "संदेश हटवा",
        "जोखीम नाही",
        "जोखीममुक्त",
    ),
    "es": (
        "engañoso",
        "falso",
        "rendimiento garantizado",
        "información privilegiada",
        "borrar mensaje",
        "sin riesgo",
    ),
    "zh": (
        "误导",
        "虚假",
        "保证收益",
        "内幕",
        "删除消息",
        "零风险",
    ),
}


# ============================================================
# DATA MODELS
# ============================================================

@dataclass
class AgentMessage:
    sender: str
    recipient: str
    message_type: str
    payload: dict[str, Any]
    trace_id: str
    timestamp: str


@dataclass
class Finding:
    finding_id: str
    case_id: str
    rule_id: str
    severity: str
    outcome: str
    rationale: str
    citation: str
    confidence: float
    status: str = "open"


@dataclass
class AgentResult:
    agent: str
    trace_id: str
    findings: list[Finding] = field(default_factory=list)
    messages: list[AgentMessage] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


# ============================================================
# HELPERS
# ============================================================

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _finding(
    scenario: dict[str, Any],
    decision: RuleDecision,
    confidence: float,
) -> Finding:
    finding_id = sha256(
        f"{scenario['case_id']}:{decision.rule_id}".encode()
    ).hexdigest()[:16]

    return Finding(
        finding_id=finding_id,
        case_id=scenario["case_id"],
        rule_id=decision.rule_id,
        severity=decision.severity,
        outcome=decision.outcome,
        rationale=decision.rationale,
        citation=decision.citation,
        confidence=calibrate_confidence(
            confidence,
            decision.rule_id,
        ),
    )


def _message(
    sender: str,
    recipient: str,
    message_type: str,
    payload: dict[str, Any],
    trace_id: str,
) -> AgentMessage:
    return AgentMessage(
        sender,
        recipient,
        message_type,
        payload,
        trace_id,
        _now(),
    )


# ============================================================
# TRANSACTION MONITOR
# ============================================================

class TransactionMonitor:
    name = "transaction_monitor"

    def run(
        self,
        scenario: dict[str, Any],
        trace_id: str,
    ) -> AgentResult:

        decisions = evaluate_rules(
            scenario,
            "transaction",
        )

        findings = [
            _finding(
                scenario,
                decision,
                0.92,
            )
            for decision in decisions
            if decision.outcome == "alert"
        ]

        context = {
            "case_id": scenario["case_id"],
            "domain": scenario["domain"],
            "jurisdiction": scenario["jurisdiction"],
            "finding_ids": [
                finding.finding_id
                for finding in findings
            ],
        }

        return AgentResult(
            self.name,
            trace_id,
            findings,
            [
                _message(
                    self.name,
                    "communication_scanner",
                    "transaction_context",
                    context,
                    trace_id,
                )
            ],
        )


# ============================================================
# COMMUNICATION SCANNER
# ============================================================

class CommunicationScanner:
    name = "communication_scanner"

    def run(
        self,
        scenario: dict[str, Any],
        trace_id: str,
    ) -> AgentResult:

        text = str(
            scenario.get("facts", "")
        ).lower()

        # ----------------------------------------------------
        # RULE ENGINE
        # ----------------------------------------------------

        scoped_decisions = [
            item
            for item in evaluate_rules(
                scenario,
                "communication",
            )
            if item.outcome == "alert"
        ]

        # ----------------------------------------------------
        # KEYWORD DETECTION
        # ----------------------------------------------------

        matched_terms = []

        for language_terms in COMMUNICATION_LEXICON.values():

            for term in language_terms:

                if term.lower() in text:
                    matched_terms.append(term)

        lexicon_hit = bool(matched_terms)

        # ----------------------------------------------------
        # SUSPICION
        # ----------------------------------------------------

        suspicious = bool(
            scoped_decisions
            or lexicon_hit
        )

        # ----------------------------------------------------
        # EVIDENCE
        # ----------------------------------------------------

        evidence_available = bool(
            scenario.get("evidence")
        )

        warnings = []

        if not evidence_available:
            warnings.append(
                "Communication evidence is absent; "
                "confidence capped at 0.65."
            )

        # ----------------------------------------------------
        # FINDINGS
        # ----------------------------------------------------

        findings = []

        # Existing rule-engine findings
        for decision in scoped_decisions:

            confidence = (
                0.88
                if evidence_available
                else 0.65
            )

            findings.append(
                _finding(
                    scenario,
                    decision,
                    confidence,
                )
            )

        # ----------------------------------------------------
        # LEXICON-BASED FINDING
        # ----------------------------------------------------

        if lexicon_hit:

            confidence = (
                0.86
                if evidence_available
                else 0.65
            )

            # Avoid duplicate finding if rule engine
            # already produced the same communication rule.
            existing_rule_ids = {
                finding.rule_id
                for finding in findings
            }

            if "COMM-LEXICON-001" not in existing_rule_ids:

                matched_preview = ", ".join(
                    matched_terms[:5]
                )

                decision = RuleDecision(
                    "COMM-LEXICON-001",
                    "alert",
                    "high",
                    (
                        "Potentially problematic communication "
                        f"language detected: {matched_preview}"
                    ),
                    (
                        "Communication surveillance policy; "
                        "human compliance review required."
                    ),
                )

                findings.append(
                    _finding(
                        scenario,
                        decision,
                        confidence,
                    )
                )

        # ----------------------------------------------------
        # MESSAGE TO NEXT AGENT
        # ----------------------------------------------------

        message_payload = {
            "case_id": scenario["case_id"],
            "suspicious": suspicious,
            "lexicon_hit": lexicon_hit,
            "matched_terms": matched_terms[:10],
            "rule_findings": len(scoped_decisions),
            "finding_count": len(findings),
        }

        return AgentResult(
            self.name,
            trace_id,
            findings,
            [
                _message(
                    self.name,
                    "regulatory_update_tracker",
                    "communication_assessment",
                    message_payload,
                    trace_id,
                )
            ],
            warnings,
        )


# ============================================================
# REGULATORY UPDATE TRACKER
# ============================================================

class RegulatoryUpdateTracker:
    name = "regulatory_update_tracker"

    def run(
        self,
        scenario: dict[str, Any],
        trace_id: str,
    ) -> AgentResult:

        text = (
            f"{scenario['title']} "
            f"{scenario['facts']}"
        ).lower()

        findings = []

        if any(
            term in text
            for term in (
                "final rule",
                "regulatory change",
                "effective in 120 days",
            )
        ):

            findings.append(
                _finding(
                    scenario,
                    RuleDecision(
                        "REGCHANGE-001",
                        "alert",
                        "medium",
                        (
                            "Regulatory change requires "
                            "preliminary impact assessment "
                            "and human validation."
                        ),
                        (
                            "SEC Swap Margin Rule; "
                            "Basel III CRE54; "
                            "EMIR Margin RTS"
                        ),
                    ),
                    0.9,
                )
            )

        if any(
            term in text
            for term in (
                "eu rule",
                "singapore",
                "cross-border sharing",
                "otc derivatives",
            )
        ):

            findings.append(
                _finding(
                    scenario,
                    RuleDecision(
                        "JURIS-001",
                        "alert",
                        "high",
                        (
                            "Conflicting jurisdictional "
                            "obligations require legal and "
                            "compliance resolution."
                        ),
                        "EU EMIR; Singapore PDPA",
                    ),
                    0.86,
                )
            )

        message = _message(
            self.name,
            "report_generator",
            "regulatory_assessment",
            {
                "jurisdiction": scenario["jurisdiction"],
                "rule_version": RULE_VERSION,
                "finding_count": len(findings),
            },
            trace_id,
        )

        return AgentResult(
            self.name,
            trace_id,
            findings,
            [message],
        )

    def assess(
        self,
        change: dict[str, Any],
        trace_id: str,
    ) -> AgentResult:

        regulatory_change = assess_change(
            change
        )

        message = _message(
            self.name,
            "report_generator",
            "regulatory_change_assessment",
            {
                "change_id": regulatory_change.change_id,
                "impact": regulatory_change.impact,
                "human_validation_required":
                    regulatory_change.human_validation_required,
            },
            trace_id,
        )

        return AgentResult(
            self.name,
            trace_id,
            [],
            [message],
        )


# ============================================================
# REPORT GENERATOR
# ============================================================

class ReportGenerator:
    name = "report_generator"

    def run(
        self,
        scenario: dict[str, Any],
        findings: list[Finding],
        trace_id: str,
    ) -> dict[str, Any]:

        severity_rank = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        max_severity = max(
            (
                item.severity
                for item in findings
            ),
            key=lambda value: severity_rank[value],
            default="low",
        )

        escalate = (
            max_severity in {"high", "critical"}
            or any(
                item.confidence < 0.75
                for item in findings
            )
        )

        return {
            "case_id": scenario["case_id"],
            "trace_id": trace_id,
            "risk": max_severity,
            "escalate": escalate,
            "finding_count": len(findings),
            "findings": [
                asdict(item)
                for item in findings
            ],
            "recommended_action": (
                "Human compliance officer review within SLA"
                if escalate
                else "Retain evidence and sample for QA"
            ),
        }


# ============================================================
# CONFLICT RESOLUTION
# ============================================================

def resolve_conflicts(
    findings: list[Finding],
) -> list[Finding]:

    """Resolve duplicate agent opinions by severity-first,
    confidence-second quorum.
    """

    grouped: dict[
        tuple[str, str],
        list[Finding]
    ] = {}

    for finding in findings:

        grouped.setdefault(
            (
                finding.case_id,
                finding.rule_id,
            ),
            [],
        ).append(finding)

    resolved = []

    for opinions in grouped.values():

        winner = max(
            opinions,
            key=lambda item: (
                {
                    "critical": 4,
                    "high": 3,
                    "medium": 2,
                    "low": 1,
                }[item.severity],
                item.confidence,
            ),
        )

        winner.status = (
            "escalated_conflict"
            if len(
                {
                    item.severity
                    for item in opinions
                }
            ) > 1
            else "open"
        )

        resolved.append(winner)

    return resolved


# ============================================================
# COMPLETE AGENT PIPELINE
# ============================================================

def run_case(
    scenario: dict[str, Any],
) -> dict[str, Any]:

    trace_id = str(uuid4())

    pipeline_started = perf_counter()

    trace_steps = [
        {
            "step": "intake",
            "agent": "orchestrator",
            "status": "accepted",
            "case_id": scenario["case_id"],
        }
    ]

    pipeline_errors: list[str] = []

    # --------------------------------------------------------
    # TRANSACTION MONITOR
    # --------------------------------------------------------

    phase_started = perf_counter()

    try:

        monitor = TransactionMonitor().run(
            scenario,
            trace_id,
        )

    except Exception as error:

        monitor = AgentResult(
            TransactionMonitor.name,
            trace_id,
            warnings=[
                f"Transaction Monitor failed: {error}"
            ],
        )

        pipeline_errors.append(
            monitor.warnings[0]
        )

    monitor_latency_ms = round(
        (perf_counter() - phase_started) * 1000,
        3,
    )

    trace_steps.append(
        {
            "step": "signal_detection",
            "agent": monitor.agent,
            "status": (
                "failed"
                if monitor.warnings
                else "completed"
            ),
            "findings": len(
                monitor.findings
            ),
        }
    )

    # --------------------------------------------------------
    # COMMUNICATION SCANNER
    # --------------------------------------------------------

    phase_started = perf_counter()

    try:

        scanner = CommunicationScanner().run(
            scenario,
            trace_id,
        )

    except Exception as error:

        scanner = AgentResult(
            CommunicationScanner.name,
            trace_id,
            warnings=[
                f"Communication Scanner failed: {error}"
            ],
        )

        pipeline_errors.append(
            scanner.warnings[0]
        )

    scanner_latency_ms = round(
        (perf_counter() - phase_started) * 1000,
        3,
    )

    trace_steps.append(
        {
            "step": "communication_assessment",
            "agent": scanner.agent,
            "status": (
                "failed"
                if scanner.warnings
                else "completed"
            ),
            "findings": len(
                scanner.findings
            ),
            "warnings": len(
                scanner.warnings
            ),
        }
    )

    # --------------------------------------------------------
    # REGULATORY UPDATE TRACKER
    # --------------------------------------------------------

    phase_started = perf_counter()

    try:

        regulatory = RegulatoryUpdateTracker().run(
            scenario,
            trace_id,
        )

    except Exception as error:

        regulatory = AgentResult(
            RegulatoryUpdateTracker.name,
            trace_id,
            warnings=[
                f"Regulatory Update Tracker failed: {error}"
            ],
        )

        pipeline_errors.append(
            regulatory.warnings[0]
        )

    regulatory_latency_ms = round(
        (perf_counter() - phase_started) * 1000,
        3,
    )

    trace_steps.append(
        {
            "step": "regulatory_assessment",
            "agent": regulatory.agent,
            "status": (
                "failed"
                if regulatory.warnings
                else "completed"
            ),
            "findings": len(
                regulatory.findings
            ),
        }
    )

    # --------------------------------------------------------
    # CONFLICT RESOLUTION + REPORT
    # --------------------------------------------------------

    phase_started = perf_counter()

    findings = resolve_conflicts(
        monitor.findings
        + scanner.findings
        + regulatory.findings
    )

    report = ReportGenerator().run(
        scenario,
        findings,
        trace_id,
    )

    if pipeline_errors:

        report["risk"] = "critical"

        report["escalate"] = True

        report["recommended_action"] = (
            "Pipeline failure: preserve evidence "
            "and require immediate human review"
        )

    report_latency_ms = round(
        (perf_counter() - phase_started) * 1000,
        3,
    )

    trace_steps.append(
        {
            "step": "conflict_resolution",
            "agent": ReportGenerator.name,
            "status": "completed",
            "findings": len(findings),
        }
    )

    trace_steps.append(
        {
            "step": "report_generation",
            "agent": ReportGenerator.name,
            "status": "completed",
            "risk": report["risk"],
            "escalate": report["escalate"],
        }
    )

    # --------------------------------------------------------
    # AUDIT
    # --------------------------------------------------------

    messages = (
        monitor.messages
        + scanner.messages
        + regulatory.messages
    )

    report["audit"] = {
        "trace_id": trace_id,
        "rule_version": RULE_VERSION,
        "calibration_version": CALIBRATION_VERSION,
        "scenario_hash": sha256(
            repr(
                sorted(
                    scenario.items()
                )
            ).encode()
        ).hexdigest(),
        "agents": [
            monitor.agent,
            scanner.agent,
            regulatory.agent,
            ReportGenerator.name,
        ],
        "trace_steps": trace_steps,
        "message_count": len(messages),
        "messages": [
            asdict(message)
            for message in messages
        ],
        "agent_findings": {
            monitor.agent: len(
                monitor.findings
            ),
            scanner.agent: len(
                scanner.findings
            ),
            regulatory.agent: len(
                regulatory.findings
            ),
        },
        "latency_ms": {
            monitor.agent: monitor_latency_ms,
            scanner.agent: scanner_latency_ms,
            regulatory.agent: regulatory_latency_ms,
            ReportGenerator.name: report_latency_ms,
            "pipeline": round(
                (
                    perf_counter()
                    - pipeline_started
                ) * 1000,
                3,
            ),
        },
        "agent_status": {
            monitor.agent: (
                "failed"
                if monitor.warnings
                else "completed"
            ),
            scanner.agent: (
                "failed"
                if scanner.warnings
                else "completed"
            ),
            regulatory.agent: (
                "failed"
                if regulatory.warnings
                else "completed"
            ),
            ReportGenerator.name: "completed",
        },
        "created_at": _now(),
        "warnings": (
            monitor.warnings
            + scanner.warnings
            + regulatory.warnings
            + pipeline_errors
        ),
    }

    return report


# ============================================================
# SCENARIO VALIDATION
# ============================================================

def validate_scenarios(
    scenarios: list[dict[str, Any]],
) -> list[dict[str, Any]]:

    reports = []

    for scenario in scenarios:

        report = run_case(
            scenario
        )

        report["expected_risk"] = (
            scenario["expected"]
        )

        no_alert = (
            scenario["expected"] == "no_alert"
            and report["finding_count"] == 0
            and not report["escalate"]
        )

        report["validation"] = (
            "pass"
            if (
                report["risk"]
                == scenario["expected"]
                or no_alert
            )
            else "fail"
        )

        reports.append(report)

    return reports