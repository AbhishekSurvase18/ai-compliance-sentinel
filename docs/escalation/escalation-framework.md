# Escalation framework

Escalate when risk is high or critical, confidence is below 0.75, evidence is missing, a conflict is detected, or a sanctions/MNPI typology is present. The reviewer must have an approved compliance role and provide identity, decision, rationale, and timestamp. Decisions are `approve`, `reject`, or `escalate` and are append-only in `review-events.jsonl`.

SLA policy: critical sanctions/MNPI alerts are immediate; high-risk cases are reviewed within the bank-defined supervisory SLA; medium cases are sampled unless evidence or jurisdiction raises risk. Approval of a critical finding is restricted to a senior compliance officer or MLRO; other reviewers may reject or escalate but cannot approve it.
