"""Authenticated API boundary for compliance event analysis."""

import os
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException

from agents import run_case
from ingestion import validate_scenario
from report import verify_audit_chain, write_report
from storage import ComplianceStore
from agents import RegulatoryUpdateTracker
from regulatory import assess_change, serialize_change


app = FastAPI(title="Compliance Sentinel API", version="1.0.0")


def require_api_key(authorization: str | None = Header(default=None)) -> None:
	expected = os.environ.get("SENTINEL_API_KEY")
	if not expected:
		raise HTTPException(status_code=503, detail="API authentication is not configured")
	if authorization != f"Bearer {expected}":
		raise HTTPException(status_code=401, detail="Invalid API credentials")


@app.get("/health")
def health() -> dict[str, Any]:
	chain_ok, chain_message = verify_audit_chain()
	return {"status": "ok" if chain_ok else "degraded", "audit_chain": chain_message, "storage": ComplianceStore().counts()}


@app.post("/v1/analyze", dependencies=[Depends(require_api_key)])
def analyze(event: dict[str, Any]) -> dict[str, Any]:
	try:
		scenario = validate_scenario(event)
	except ValueError as error:
		raise HTTPException(status_code=422, detail=str(error)) from error
	report = run_case(scenario)
	write_report(report)
	return report


@app.post("/v1/analyze/batch", dependencies=[Depends(require_api_key)])
def analyze_batch(events: list[dict[str, Any]]) -> dict[str, Any]:
	if not events:
		raise HTTPException(status_code=422, detail="events must contain at least one item")
	reports = []
	errors = []
	for position, event in enumerate(events):
		try:
			scenario = validate_scenario(event, position)
			report = run_case(scenario)
			write_report(report)
			reports.append(report)
		except ValueError as error:
			errors.append(str(error))
	return {"processed": len(reports), "rejected": len(errors), "errors": errors, "reports": reports}


@app.get("/v1/storage/counts", dependencies=[Depends(require_api_key)])
def storage_counts() -> dict[str, int]:
	return ComplianceStore().counts()


@app.post("/v1/regulatory/assess", dependencies=[Depends(require_api_key)])
def assess_regulatory_change(change: dict[str, Any]) -> dict[str, Any]:
	try:
		result = RegulatoryUpdateTracker().assess(change, "regulatory-api")
	except ValueError as error:
		raise HTTPException(status_code=422, detail=str(error)) from error
	return {"change": serialize_change(assess_change(change)), "message": result.messages[0].payload}
