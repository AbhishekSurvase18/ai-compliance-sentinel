# Audit trail

The local report includes a scenario hash, immutable finding IDs, and ordered `trace_steps` from intake through signal detection, communication assessment, regulatory assessment, conflict resolution, and report generation. Production storage must be WORM/SEC 17a-4(f) compatible, append-only, replicated, access-controlled, and cryptographically signed. Each event should include the previous event hash to make tampering detectable. NTP synchronization, clock-skew tolerance, retention locks, export testing, and restore drills are mandatory controls.
