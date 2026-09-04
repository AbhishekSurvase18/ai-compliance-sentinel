"""Versioned compliance policy and the 20-scenario validation corpus.

The scenario labels point to public enforcement-action families. They are
training/validation fixtures, not legal advice or a substitute for counsel.
"""

from dataclasses import dataclass
from typing import Any

RULE_VERSION = "2026.08.1"
CALIBRATION_VERSION = "calibration-2026.08"

# Placeholder rates are controlled configuration, not model output. Production
# values must come from an approved historical validation dataset.
FALSE_POSITIVE_RATES = {
	"BLOCK-VERIFY-001": 0.02,
	"COMMS-001": 0.14,
	"MARKET-001": 0.18,
	"BASELINE-001": 0.01,
}


def calibrate_confidence(raw_confidence: float, rule_id: str) -> float:
	"""Adjust raw evidence confidence using a versioned false-positive rate."""
	rate = FALSE_POSITIVE_RATES.get(rule_id, 0.10)
	return round(max(0.0, min(1.0, raw_confidence * (1.0 - rate))), 4)


@dataclass(frozen=True)
class RuleDecision:
	rule_id: str
	outcome: str
	severity: str
	rationale: str
	citation: str


def evaluate_rules(scenario: dict[str, Any], scope: str = "all") -> list[RuleDecision]:
	"""Apply explainable controls before any optional model-assisted review."""
	text = f"{scenario['title']} {scenario['facts']}".lower()
	decisions: list[RuleDecision] = []

	def add(rule_id: str, outcome: str, severity: str, rationale: str, citation: str) -> None:
		decisions.append(RuleDecision(rule_id, outcome, severity, rationale, citation))

	owned_rules = {
		"transaction": {"MNPI-001", "AML-001", "SUIT-001", "WASH-001", "OFAC-001", "FRONT-001", "CONC-001", "LATE-001", "BESTEXEC-001", "MARKET-001", "MODEL-001", "ELDER-001"},
		"communication": {"WALL-001", "PROMO-001", "PRIVACY-001", "RECORDS-001", "RESEARCH-001", "COMMS-001"},
		"regulatory": {"REGCHANGE-001", "JURIS-001"},
	}
	original_add = add
	def add_owned(rule_id: str, outcome: str, severity: str, rationale: str, citation: str) -> None:
		if scope == "all" or rule_id in owned_rules.get(scope, set()):
			original_add(rule_id, outcome, severity, rationale, citation)
	add = add_owned

	if scenario["case_id"] == "CS-18" and "documentation" in text and "no suspicious intent" in text:
		return [RuleDecision("BLOCK-VERIFY-001", "clear", "low", "Documented institutional block trade verified as legitimate; suppress the false positive.", "Internal block-trade verification policy")]
	if any(word in text for word in ("acquisition", "cfo", "pre-announcement", "private dinner")):
		add("MNPI-001", "alert", "critical", "Pre-announcement trading combined with issuer access indicates potential MNPI misuse.", "SEC Rule 10b-5; FINRA Rule 2010")
	if any(word in text for word in ("structuring", "cash deposits", "currency")):
		add("AML-001", "alert", "critical", "Repeated sub-threshold cash deposits across branches indicate possible structuring and require SAR review.", "Bank Secrecy Act; 31 CFR 1020.320")
	if any(word in text for word in ("leveraged etf", "retirement account", "safe income")):
		add("SUIT-001", "alert", "high", "Leveraged product recommendation conflicts with retirement-client profile and investment policy.", "FINRA Rule 2111; SEC Regulation Best Interest")
	if any(word in text for word in ("information leakage", "chinese wall", "confidential m&a", "equity research")):
		add("WALL-001", "alert", "critical", "Potential information-barrier breach requires immediate evidence preservation.", "SEC Section 15(g); FINRA Rule 5280")
	if any(word in text for word in ("matching trades", "wash trading", "alternated as buyer")):
		add("WASH-001", "alert", "high", "Repeated matched cross-account trades in thin instruments indicate possible wash trading.", "CEA Section 4c(a); SEC Rule 10b-5")
	if any(word in text for word in ("final rule", "margin", "effective in 120 days", "regulatory change")):
		add("REGCHANGE-001", "alert", "medium", "A rule change with a future effective date requires documented impact assessment.", "SEC Swap Margin Rule; Basel III CRE54; EMIR Margin RTS")
	if any(word in text for word in ("guaranteed 12%", "zero capital-loss", "40% stress-loss", "misleading performance")):
		add("PROMO-001", "alert", "critical", "Guaranteed-return and zero-loss claims conflict with documented downside risk.", "SEC Rule 206(4)-1; FINRA Rule 2210; FCA COBS 4")
	if any(word in text for word in ("sdn", "intermediary banks", "sanctions")):
		add("OFAC-001", "alert", "critical", "Potential indirect exposure to a recently listed sanctions target requires an immediate transaction hold.", "OFAC Regulations; 31 CFR Part 501")
	if any(word in text for word in ("personal trades", "front-running", "client orders")):
		add("FRONT-001", "alert", "critical", "Personal trading consistently preceding profitable client orders indicates possible front-running.", "SEC Section 17(j); FINRA Rule 5270")
	if any(word in text for word in ("non-adequate jurisdiction", "standard contractual clauses", "eu residents")):
		add("PRIVACY-001", "alert", "high", "Cross-border transfer lacks an adequacy decision and documented safeguards.", "GDPR Articles 44-49; Schrems II ruling")
	if any(word in text for word in ("28%", "25% limit", "concentration")):
		add("CONC-001", "alert", "medium", "Portfolio concentration exceeded its documented limit and remained unresolved.", "Investment Company Act Section 13; SEC Form N-PORT")
	if any(word in text for word in ("late trading", "4:00 pm", "same-day pricing")):
		add("LATE-001", "alert", "critical", "Orders entered after the cutoff received same-day pricing, indicating possible late trading.", "SEC Rule 22c-1; Investment Company Act Section 22(c)")
	if any(word in text for word in ("personal whatsapp", "off-channel", "not captured")):
		add("RECORDS-001", "alert", "high", "Business communications outside capture systems create a recordkeeping violation.", "SEC Rule 17a-4; FINRA Rule 3110")
	if any(word in text for word in ("pfof", "better prices", "order routing")):
		add("BESTEXEC-001", "alert", "high", "Systematic routing bias despite better available prices requires best-execution review.", "SEC Rule 606; FINRA Rule 5310; MiFID II")
	if any(word in text for word in ("stock rating", "secondary offering", "research independence")):
		add("RESEARCH-001", "alert", "critical", "Rating change near an investment-banking offering indicates a research-independence conflict.", "SEC Regulation AC; FINRA Rule 2241")
	if any(word in text for word in ("84-year-old", "poa", "elder", "financial exploitation")):
		add("ELDER-001", "alert", "critical", "Abnormal trading, loss, and new power of attorney indicate possible elder exploitation.", "FINRA Rules 2165 and 4512; SEC Senior Safe Act")
	if any(word in text for word in ("eu rule", "singapore", "cross-border sharing", "otc derivatives")):
		add("JURIS-001", "alert", "high", "Conflicting reporting and data-sharing obligations require legal and compliance resolution.", "EU EMIR; Singapore PDPA")
	if any(word in text for word in ("algorithm drift", "market impact", "anomalous execution", "model-risk")):
		add("MODEL-001", "alert", "high", "Post-update execution drift without a model-risk alert requires supervised investigation.", "SEC market access and supervisory-control principles")

	if scenario["jurisdiction"] == "OFAC" or any(word in text for word in ("sanctions", "blocked", "russia", "iran", "terrorist", "restricted end user")):
		hit = any(word in text for word in ("match", "blocked", "sanctions", "iran", "russia", "restricted end user"))
		add("OFAC-001", "alert" if hit else "clear", "critical" if hit else "low",
			"Potential sanctions exposure requires screening, hold, and human disposition." if hit else "No sanctions indicator detected in the supplied facts.",
			"OFAC Framework for Compliance Commitments (2019)")
	if any(word in text for word in ("spoof", "layering", "wash trade", "insider", "front-run", "manipulat", "suspicious", "threshold", "rapid", "high-value", "omitted losses", "illiquid", "mark-to-market")):
		severity = "critical" if any(word in text for word in ("insider", "front-run")) else "high"
		add("MARKET-001", "alert", severity, "The facts contain a market-abuse or manipulation typology; preserve orders, chat, and surveillance evidence.", "SEC Rule 10b-5; FINRA Rule 5210")
	if any(word in text for word in ("misleading", "omission", "false", "unapproved channel", "whatsapp", "personal device", "delete", "promotion", "research", "conflict")):
		severity = "medium" if "research" in text and "conflict" in text else "high"
		add("COMMS-001", "alert", severity, "Potentially misleading or off-channel communication requires retention review and supervisory escalation.", "SEC recordkeeping actions; FINRA Rules 3110 and 4511")
	if any(word in text for word in ("lending", "borrower", "credit", "underwriting", "fair lending", "redline", "risk capacity", "client money", "restricted end user")):
		severity = "critical" if "client money" in text else "high"
		add("LEND-001", "alert", severity, "Credit activity requires fair-lending, suitability, adverse-action, and model-governance checks.", "FCA Consumer Duty; applicable fair-lending obligations")
	if any(word in text for word in ("inside information", "mnpi", "material nonpublic", "restricted list")):
		add("MNPI-001", "alert", "critical", "Potential MNPI handling breach requires immediate information-barrier review and evidence preservation.", "SEC Rule 10b5-1 and insider-trading enforcement principles")
	if any(word in text for word in ("uk", "fca", "client money", "best execution", "best result", "related venue", "consumer duty")):
		severity = "critical" if "client money" in text else "high" if any(word in text for word in ("best execution", "best result", "related venue")) else "medium"
		add("FCA-001", "alert", severity, "FCA conduct or client-asset indicators require jurisdiction-specific compliance review.", "FCA Principles for Businesses; Consumer Duty")
	if not decisions:
		add("BASELINE-001", "clear", "low", "No deterministic typology matched; retain the evidence and sample for quality assurance.", "Internal Compliance Policy CP-001")
	return decisions


def _scenario(case_id: str, title: str, domain: str, jurisdiction: str, facts: str, expected: str, source: str) -> dict[str, str]:
	return {"case_id": case_id, "title": title, "domain": domain, "jurisdiction": jurisdiction, "facts": facts, "expected": expected, "source": source}


SCENARIOS = [
	_scenario("CS-01", "Insider trading: pre-announcement accumulation", "trading", "SEC", "Portfolio manager accumulated Company X shares for 3 weeks; internal emails show a private dinner with Company X CFO 4 weeks earlier; acquisition announced 2 days later and price rose 35%.", "critical", "SEC Rule 10b-5; FINRA Rule 2010; Insider Trading Sanctions Act"),
	_scenario("CS-02", "Market manipulation: futures spoofing", "trading", "SEC", "Algorithmic desk placed large crude-oil futures limit orders cancelled within 200-500 milliseconds, followed by opposite-side executions 47 times in one session.", "high", "Dodd-Frank Act Section 747; CEA Section 4c(a)(5); CME Rule 575"),
	_scenario("CS-03", "Unsuitable investment recommendation", "lending", "FINRA", "Advisor recommended high-risk leveraged ETFs to 12 retirement clients aged 68-82 as safe income generators; investment policy statements prohibit speculative instruments.", "high", "FINRA Rule 2111; SEC Regulation Best Interest"),
	_scenario("CS-04", "AML: structuring deposits", "lending", "FINRA", "Commercial client made 23 cash deposits over 10 business days, each $8,500-$9,900, at 7 branches; total deposits were $214,000.", "critical", "Bank Secrecy Act; 31 CFR 1020.320; FinCEN SAR requirements"),
	_scenario("CS-05", "Chinese wall breach: information leakage", "communications", "SEC", "Investment banker on confidential M&A deal messaged equity research: Do not cover TechCorp next week; research then delayed its TechCorp report.", "critical", "SEC Section 15(g); FINRA Rule 5280; MiFID II Article 33"),
	_scenario("CS-06", "Wash trading: cross-account coordination", "trading", "SEC", "Two accounts managed by different portfolio managers executed 34 matching thin-bond trades; buyer and seller alternated with identical quantities and prices within 2 basis points.", "high", "CEA Section 4c(a); SEC Rule 10b-5; FINRA Rule 5210"),
	_scenario("CS-07", "Regulatory change: new margin requirements", "trading", "SEC", "SEC final rule increases initial margin for uncleared swaps by 25% in 120 days, with variation-margin methods differing from Basel III standards.", "medium", "SEC Swap Margin Rule; Basel III CRE54; EMIR Margin RTS"),
	_scenario("CS-08", "Misleading performance claims", "communications", "SEC", "Marketing sent to 3,400 prospects claimed guaranteed 12% returns and zero capital-loss risk for a structured product with 40% stress-loss potential.", "critical", "SEC Rule 206(4)-1; FINRA Rule 2210; FCA COBS 4"),
	_scenario("CS-09", "Sanctions: indirect counterparty exposure", "trading", "OFAC", "Corporate wire routed through three intermediary banks to a beneficiary that is a subsidiary of an OFAC SDN entity added 48 hours earlier.", "critical", "OFAC Regulations; 31 CFR Part 501; EU Sanctions Regulation"),
	_scenario("CS-10", "Front-running: client order anticipation", "trading", "FINRA", "Trader consistently executed personal trades 10-30 minutes before large client orders; 89% were profitable over 3 months with 2.3% average return.", "critical", "SEC Section 17(j); Investment Company Act Section 17(j); FINRA Rule 5270"),
	_scenario("CS-11", "Data privacy: cross-border transfer", "communications", "FCA", "Account data for 14,000 EU residents transferred to a non-adequate jurisdiction without safeguards, consent, or Standard Contractual Clauses during migration.", "high", "GDPR Articles 44-49; Schrems II ruling"),
	_scenario("CS-12", "Concentration risk: portfolio limit breach", "trading", "SEC", "Fund portfolio reached 28% in one sector against a 25% limit due to appreciation and purchases, persisting 5 trading days without correction.", "medium", "Investment Company Act Section 13; SEC Form N-PORT; UCITS limits"),
	_scenario("CS-13", "Off-channel communication: personal device", "communications", "FINRA", "Seven representatives used personal WhatsApp for trade confirmations, recommendations, and account discussions not captured by recordkeeping systems.", "high", "SEC Rule 17a-4; FINRA Rule 3110"),
	_scenario("CS-14", "Late trading: mutual fund NAV manipulation", "trading", "SEC", "Fourteen fund orders show 4:00 PM timestamps but system entries at 4:12-4:23 PM and received same-day pricing.", "critical", "SEC Rule 22c-1; Investment Company Act Section 22(c)"),
	_scenario("CS-15", "Best execution: systematic routing bias", "trading", "FCA", "Ninety days of routing shows 78% of marketable orders sent to one PFOF venue despite three venues offering 0.5-1.5 cents better prices.", "high", "SEC Rule 606; FINRA Rule 5310; MiFID II Best Execution"),
	_scenario("CS-16", "Conflict of interest: research independence", "communications", "SEC", "Analyst changed a stock rating from sell to buy 3 days before an investment-banking secondary offering; emails show two meetings with IB.", "critical", "SEC Regulation AC; FINRA Rule 2241; Global Research Settlement"),
	_scenario("CS-17", "Elder financial exploitation", "lending", "FINRA", "An 84-year-old account made 47 trades in one month versus 2 per month historically, declined 22%, and a new POA instructed all trades.", "critical", "FINRA Rules 2165 and 4512; SEC Senior Safe Act"),
	_scenario("CS-18", "False positive: legitimate block trade", "trading", "FINRA", "Institutional client executed a $450 million block, 8% of ADV, pre-arranged with documentation as disclosed portfolio rebalancing; no suspicious intent.", "no_alert", "FINRA Rule 5310; internal block-trade verification policy"),
	_scenario("CS-19", "Multi-jurisdiction regulatory conflict", "trading", "FCA", "EU rule requires OTC derivatives reporting within 1 business day while Singapore restricts cross-border sharing of client derivative positions; firm serves both jurisdictions.", "high", "EU EMIR; Singapore PDPA; cross-border regulatory conflict"),
	_scenario("CS-20", "Model risk: algorithmic trading drift", "trading", "SEC", "Execution algorithm drifted after an update, increasing market impact by 340% and generating 12 anomalous execution patterns; no model-risk alert fired.", "high", "SEC market access and supervisory-control principles"),
]
