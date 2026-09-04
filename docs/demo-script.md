# Five-minute demonstration script

## 1. Open the console

Run `python -m streamlit run app.py` and open `http://localhost:8501`. Point out the validated scenario count, escalation count, critical/high exposure, stored reports, and audit-chain status.

## 2. Trace a critical case

Select `CS-01`. Explain the transaction signal, Communication Scanner handoff, Regulatory Update Tracker context, Report Generator risk aggregation, confidence, citation, trace ID, and human-review action.

## 3. Demonstrate false-positive control

Select `CS-18`. Show `NO ALERT` behavior: zero findings and no escalation because documentation confirms a legitimate block trade.

## 4. Demonstrate human review

Configure `SENTINEL_USERS`, sign in, select a case, submit a decision and rationale. Show that reviewer identity, role, timestamp, and decision are written to the append-only review log and SQLite store.

## 5. Demonstrate ingestion

Upload a JSON event through `Ingest external events`. Show successful validation and analysis. Upload malformed JSON or a missing field and show quarantine/error handling.

## 6. Demonstrate reproducibility and integrity

Run `python app.py` and show 20/20 validation. Explain scenario hash, rule version, deterministic finding ID, and hash-chain verification. Mention that production uses WORM storage and SSO rather than local files.
