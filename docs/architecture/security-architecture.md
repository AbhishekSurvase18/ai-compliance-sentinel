# Security architecture

Production controls: SSO plus MFA for reviewers; least-privilege service identities; encryption in transit and at rest; secrets in a managed vault; tenant and jurisdiction data boundaries; field-level redaction in logs; signed service-to-service envelopes; malware scanning on evidence; prompt-injection isolation; and WORM retention for audit records.

No model or agent may release a sanctions hold, close a critical alert, or alter a historical report. Reviewer actions require role authorization and rationale.
