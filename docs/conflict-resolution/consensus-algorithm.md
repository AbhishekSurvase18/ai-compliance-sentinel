# Consensus algorithm

Group opinions by `(case_id, rule_id)`. Rank severity as critical=4, high=3, medium=2, low=1, then rank confidence. Select the maximum tuple as the operational finding, retain all original opinions, and set `status=escalated_conflict` when severities differ. Any unresolved policy disagreement, low confidence, or critical result requires human review. This is implemented by `agents.resolve_conflicts`.
