# PEGASUS-X architecture

```mermaid
flowchart LR
  UI[Dashboard] --> API[FastAPI]
  API --> ORCH[Orchestrator]
  ORCH --> RT[Red Team]
  RT --> BT[Blue Team Detection]
  BT --> TH[Threat Hunter]
  TH --> DEF[Blue Team Defense]
  DEF --> SA[Security Analyst]
  SA --> DB[(SQLite events, reports, checkpoints)]
  BT -. optional explanation .-> GROQ[Groq API]
  API -. read-only connectivity check .-> PG[(PostgreSQL in isolated VM)]
```

The Red Team's scenario runner is deliberately bounded to synthetic telemetry and harmless control-validation events. PostgreSQL connectivity does not execute attack payloads.
