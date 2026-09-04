"""Official-source registry and preliminary regulatory-change assessment."""

from dataclasses import asdict, dataclass
from datetime import date
from typing import Any


OFFICIAL_FEEDS = {
	"SEC": "https://www.sec.gov/news/pressreleases",
	"FINRA": "https://www.finra.org/rules-guidance/notices",
	"FCA": "https://www.fca.org.uk/news",
	"OFAC": "https://ofac.treasury.gov/recent-actions",
	"OCC": "https://www.occ.gov/news-issuances/index-news-issuances.html",
	"MAS": "https://www.mas.gov.sg/regulation",
}


@dataclass(frozen=True)
class RegulatoryChange:
	change_id: str
	source: str
	title: str
	effective_date: str | None
	jurisdictions: list[str]
	domains: list[str]
	impact: str
	human_validation_required: bool = True


def assess_change(change: dict[str, Any]) -> RegulatoryChange:
	required = {"change_id", "source", "title", "jurisdictions", "domains"}
	missing = required - change.keys()
	if missing:
		raise ValueError(f"regulatory change missing fields: {', '.join(sorted(missing))}")
	if change["source"] not in OFFICIAL_FEEDS:
		raise ValueError("regulatory source must be an approved official feed")
	if not isinstance(change["jurisdictions"], list) or not isinstance(change["domains"], list):
		raise ValueError("jurisdictions and domains must be arrays")
	date_value = change.get("effective_date")
	if date_value:
		try:
			date.fromisoformat(date_value)
		except ValueError as error:
			raise ValueError("effective_date must use YYYY-MM-DD") from error
	impact = "high" if len(change["jurisdictions"]) > 1 or len(change["domains"]) > 1 else "medium"
	return RegulatoryChange(str(change["change_id"]), str(change["source"]), str(change["title"]), date_value, [str(item) for item in change["jurisdictions"]], [str(item) for item in change["domains"]], impact)


def serialize_change(change: RegulatoryChange) -> dict[str, Any]:
	return asdict(change)
