# Compliance Sentinel

Production-oriented reference architecture for four bounded compliance agents at a tier-2 global bank. The local implementation is deterministic by design: optional LLMs may enrich evidence, but they cannot override versioned policy decisions without a human approval record.

## Architecture

`Transaction Monitor` detects trading, lending, sanctions, MNPI, and transaction typologies. `Communication Scanner` evaluates channel, retention, promotion, and misleading-communication signals. `Regulatory Update Tracker` attaches jurisdiction and rule-version context. `Report Generator` resolves findings, assigns risk, creates remediation, and decides human escalation.

Agents exchange typed `AgentMessage` envelopes containing sender, recipient, message type, payload, trace ID, and UTC timestamp. Duplicate findings use severity-first, confidence-second resolution; disagreement is marked `escalated_conflict`. High/critical findings and low-confidence findings enter human review. Every report includes a scenario hash, rule version, agent list, trace ID, timestamp, citations, and warnings.

## Project navigation

- PDF requirement mapping: `docs/requirements-traceability.md`
- Five-minute demonstration: `docs/demo-script.md`
- Operations and incident handling: `docs/operator-runbook.md`
- Architecture and protocols: `docs/architecture/` and `docs/protocols/`
- Scenario trace-throughs: `tests/scenarios/`

## Run

```powershell
python app.py
python -m streamlit run app.py
python -m unittest discover -s tests -v
docker build -t compliance-sentinel .
docker run --rm -p 8501:8501 compliance-sentinel
```

The headless command validates all 20 fixtures and writes JSON audit reports to `reports/`. The Streamlit console presents the queue and audit trail.

The Regulatory Update Tracker validates changes against approved official-source feeds, extracts effective dates, classifies preliminary impact, and marks every assessment for human validation. The authenticated API exposes this as `POST /v1/regulatory/assess`.

### API

The optional authenticated API exposes `GET /health`, `POST /v1/analyze`, `POST /v1/analyze/batch`, and `GET /v1/storage/counts`. Start it with:

```powershell
$env:SENTINEL_API_KEY='use-a-managed-secret'
python -m uvicorn api:app --host 127.0.0.1 --port 8000
```

Send `Authorization: Bearer <key>` and a scenario JSON object to `/v1/analyze`. The API validates input before invoking the four-agent pipeline and persists the report plus audit event.

For the two-service deployment, set `SENTINEL_API_KEY` and run `docker compose up --build`. The dashboard is on port 8501 and the API is on port 8000. The shared `compliance_reports` volume preserves reports across container restarts; production should replace it with managed immutable storage.

### Reviewer authentication

Configure users through an environment variable. Passwords are PBKDF2-SHA256 hashes, never plaintext credentials:

```powershell
$env:SENTINEL_USERS='{"reviewer-1":{"role":"compliance_officer","password_hash":"sentinel$<hash>"}}'
python -m streamlit run app.py
```

Generate a hash with `python -c "from auth import make_password_hash; print(make_password_hash('your-password', 'random-salt'))"`. Use SSO/OIDC and a managed secret store instead of this local login for production.

Automated tests cover all 20 expected outcomes, typed agent handoffs, conflict resolution, deterministic finding IDs, and human-review validation. The container serves Streamlit on port 8501.

## Validation corpus

The 20 fixtures are representative typologies drawn from public SEC, FCA, FINRA, and OFAC enforcement-action families. They are not copies of enforcement documents and are not legal advice. Before production use, Compliance Legal must map each fixture and rule citation to the bank's approved policy library, jurisdictional obligations, retention schedule, model-risk controls, and SLAs.

## Production hardening

Replace local filesystem persistence with WORM/object storage and an append-only event bus; add authenticated APIs, RBAC/ABAC, encryption and redaction, provider timeouts/retries, prompt-injection defenses, model/version registry, immutable metrics and distributed tracing, disaster recovery, data residency controls, and an explicit reviewer approval/rejection API. A model must never autonomously release a sanctions hold or close a high-risk alert.
