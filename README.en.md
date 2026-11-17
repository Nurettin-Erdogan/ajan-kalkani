# Ajan Kalkanı — AI Agent Runtime Security Gateway

[Live demo](https://ajan-kalkani.vercel.app/) · [Turkish README](README.md) · [Architecture](docs/ARCHITECTURE.md) · [Threat model](docs/THREAT_MODEL.md)

Ajan Kalkanı is a **runtime security gateway** and deterministic sandbox for AI agents with tool access. It constrains tool calls with operator-defined capability contracts and fails CI when covered security regressions reappear.

| | |
| --- | --- |
| **Problem** | Prompt injection can steer an agent into calling file, email, or webhook tools with real side effects |
| **Approach** | Default-deny capability contracts evaluated *before* tool execution |
| **Proof** | Side-by-side unprotected vs guarded runs, explainable decisions, SQLite hash-chained audit, 89 automated tests |

## Why not “just prompt the model”?

“Do not leak secrets” is a behavioral wish. It does not technically stop `file.read` or `webhook.post`. Ajan Kalkanı sits between the agent and its tools so risky calls can be denied before they run.

## Capability contract (example)

```yaml
task: Read the latest email and prepare a reply draft without sending it.
allow:
  - email.read_latest
  - email.create_draft
deny:
  - file.*
  - webhook.post
  - email.send
approval_required:
  - calendar.delete_*
```

## Core guarantees (MVP)

- **Default deny** for capabilities missing from the contract
- **Explicit deny wins** over allow
- **Sensitive-label egress block** toward external sinks
- **Parameter-bound human approval**: an approval is tied to the session, the call's canonical SHA-256 fingerprint and a short lifetime, and can be spent once. Redirecting an approved email (`approval.parameters-mismatch`) or replaying an approved payment (`approval.replayed`) is blocked, and an approval can never override a deny
- **Separate approver identity**: approval endpoints require `AJAN_KALKANI_APPROVER_TOKEN` (constant-time comparison) and fail closed with `503` when it is not configured; concurrent requests cannot double-spend an approval
- **Deterministic comparison** of the same attack in unprotected vs guarded mode
- **Explainable decisions** with matching rule + risk level
- **Agent CI** evaluation that can fail the pipeline on regressions

> This project does **not** claim to “solve” prompt injection. The model may still choose badly; the goal is least privilege and pre-execution enforcement.

## Stack

Python 3.11+ · FastAPI · Pytest · SQLite audit · deterministic fake tools · GitHub Actions / CodeQL · Docker

## Live sandbox

https://ajan-kalkani.vercel.app/

Synthetic only — no real email, files, calendars, or webhooks. Mutating `/api/*` calls are soft rate-limited per IP. Interactive Swagger/ReDoc stay **local-only** on the public deployment.

```bash
python -m pip install -e ".[dev]"
python -m ajan_kalkani --reload
pytest
```

Full Turkish documentation: [README.md](README.md).
