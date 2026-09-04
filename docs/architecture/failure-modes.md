# Failure modes

| Failure | Detection | Response |
|---|---|---|
| Agent timeout | Queue deadline metric | Retry with idempotency key, then escalate |
| Malformed input | Schema validation | Quarantine and request corrected data |
| Missing evidence | Confidence warning | Human review; never infer clearance |
| Conflicting findings | Severity/confidence resolver | Preserve opinions and mark conflict |
| Rule service unavailable | Health check | Fail closed for sanctions and critical paths |
| Audit store unavailable | Write acknowledgement timeout | Stop finalization and page on-call |
| Model/provider drift | Version and evaluation metrics | Roll back and open model-risk review |
