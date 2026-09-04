# PDF requirements traceability

Version: 1.0 | Date: 2026-08-24

| PDF requirement | Implementation evidence | Verification |
|---|---|---|
| Four specialized agents | `agents.py`, `docs/agents/` | `test_report_captures_all_four_agents` |
| Trading surveillance | TM rules and CS-01, 02, 06, 10, 12, 14, 15, 18, 20 | `validate_scenarios` |
| Communication surveillance | CS agent and CS-05, 08, 13, 16 | `test_agent_handoff_has_trace_and_recipient` |
| Regulatory change management | RU agent, CS-07, CS-19 | `test_regulatory_tracker_emits_assessment` |
| Official feed monitoring | allowlisted bounded HTTPS fetcher | feed allowlist test |
| Inter-agent messaging | `AgentMessage`, JSON schema, routing docs | handoff test |
| Conflict resolution | severity/confidence resolver | conflict test |
| Human escalation | `review.py`, authenticated reviewer form | review tests |
| Audit integrity | hash chain, SQLite event store, verification | tamper test |
| Reproducibility | deterministic rule version, scenario hash, finding IDs | deterministic ID test |
| Confidence calibration | versioned false-positive rates and bounded confidence | calibration test |
| External ingestion | `ingestion.py`, JSON upload, API | ingestion test |
| False-positive control | CS-18 documented block-trade suppression | false-positive test |
| Observability | runtime latency, agent status, message count, dashboard | report audit fields |
| Deployment | Dockerfiles, Compose, CI workflow | CI build job |

## Known production controls

Local SQLite and JSONL are reference substitutes. Production requires WORM/retention-locked storage, SSO/OIDC, managed secrets, signed events, NTP monitoring, data residency controls, and compliance/legal approval of every rule citation.
