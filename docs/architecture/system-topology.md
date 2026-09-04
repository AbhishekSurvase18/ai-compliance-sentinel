# System topology

Version: 1.0 | Rule set: 2026.08.1

```mermaid
flowchart LR
 S[Trading, lending, communications] --> TM[TM-01 Transaction Monitor]
 S --> CS[CS-01 Communication Scanner]
 TM --> RU[RU-01 Regulatory Update Tracker]
 CS --> RU
 TM --> RG[RG-01 Report Generator]
 CS --> RG
 RU --> RG
 RG --> H[Compliance reviewer]
 RG --> A[(WORM audit store)]
 H --> A
```

The local reference implementation executes a deterministic pipeline in `agents.run_case`. Production deployment should place each agent behind an authenticated queue and persist every envelope and decision to append-only WORM storage.
