"""Validated ingestion boundary for external compliance events."""

import json
from dataclasses import dataclass
from typing import Any


REQUIRED_FIELDS = {"case_id", "title", "domain", "jurisdiction", "facts", "expected", "source"}
VALID_DOMAINS = {"trading", "lending", "communications"}
VALID_RISKS = {"no_alert", "low", "medium", "high", "critical"}


@dataclass(frozen=True)
class IngestionResult:
	scenarios: list[dict[str, str]]
	errors: list[str]


def validate_scenario(value: Any, position: int = 0) -> dict[str, str]:
	if not isinstance(value, dict):
		raise ValueError(f"event {position}: expected an object")
	missing = REQUIRED_FIELDS - value.keys()
	if missing:
		raise ValueError(f"event {position}: missing fields: {', '.join(sorted(missing))}")
	scenario = {field: str(value[field]).strip() for field in REQUIRED_FIELDS}
	if not scenario["case_id"] or not scenario["facts"]:
		raise ValueError(f"event {position}: case_id and facts cannot be empty")
	if scenario["domain"] not in VALID_DOMAINS:
		raise ValueError(f"event {position}: unsupported domain {scenario['domain']}")
	if scenario["expected"] not in VALID_RISKS:
		raise ValueError(f"event {position}: unsupported expected risk {scenario['expected']}")
	return scenario


def load_json_events(raw: str) -> IngestionResult:
	try:
		payload = json.loads(raw)
	except json.JSONDecodeError as error:
		return IngestionResult([], [f"invalid JSON: {error.msg}"])
	values = payload if isinstance(payload, list) else [payload]
	scenarios: list[dict[str, str]] = []
	errors: list[str] = []
	for position, value in enumerate(values):
		try:
			scenarios.append(validate_scenario(value, position))
		except ValueError as error:
			errors.append(str(error))
	return IngestionResult(scenarios, errors)
