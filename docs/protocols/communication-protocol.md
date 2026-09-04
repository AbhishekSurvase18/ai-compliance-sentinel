# Communication protocol

Every `AgentMessage` contains `sender`, `recipient`, `message_type`, `payload`, `trace_id`, and UTC `timestamp`. Messages are immutable, idempotent by trace plus message type, schema-validated, and routed only to declared recipients. Priority is critical > high > medium > low. A failed delivery is retried with bounded backoff; exhausted retries become a human escalation.

The Python contract is `agents.AgentMessage`. Payloads contain only the minimum metadata required by the recipient; raw facts, communications, credentials, and unnecessary personal data are excluded from handoffs and audit messages.
