# Data flow

1. Source events are normalized to a scenario with jurisdiction, domain, facts and evidence.
2. TM-01 and CS-01 evaluate bounded typologies and emit findings.
3. RU-01 attaches jurisdiction and version context.
4. RG-01 resolves duplicates, computes maximum severity, and sets escalation.
5. Reports are serialized with trace ID, scenario hash, citations, agent list and rule version.
6. A human reviewer records an append-only decision in `reports/review-events.jsonl`.

Missing evidence lowers confidence and cannot silently become a clear decision.
