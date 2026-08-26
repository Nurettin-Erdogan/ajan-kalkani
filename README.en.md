# Ajan Kalkanı — AI Agent Runtime Security Gateway

Ajan Kalkanı is a runtime security gateway and deterministic test environment for AI agents with tool access. It constrains tool calls with operator-defined capability contracts and evaluates security regressions in CI.

## Why it exists

Prompt-level instructions such as “do not leak secrets” are behavioral expectations; they do not technically prevent an agent from calling a file, email, webhook or payment tool. Ajan Kalkanı places an authorization layer between the agent and its tools so risky calls can be denied before they execute.

## Core ideas

- **Default deny:** capabilities not present in the contract are rejected.
- **Explicit deny wins:** deny rules take precedence over allow rules.
- **Sensitive-data egress protection:** sensitive labels cannot be sent to external sinks.
- **Human approval:** selected high-risk capabilities can require explicit approval.
- **Deterministic comparison:** the same attack scenario can be run in unprotected and guarded modes.
- **Explainable decisions:** every authorization result records the matching rule and risk level.
- **Agent CI:** security scenarios are evaluated automatically and regressions can fail the pipeline.

## Example capability contract

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

If an email contains a prompt-injection instruction asking the agent to read a secret file and send it to a webhook, the requested capabilities remain outside the allowed contract and are blocked before execution.

## Stack

- Python 3.11+
- FastAPI
- Pytest
- SQLite audit history
- Deterministic fake tools and attack scenarios
- GitHub Actions / CodeQL
- Docker

## Validation

The repository includes automated tests and an evaluation pipeline that tracks guarded task success, attack success, false blocking and denied tool calls. Covered security regressions can stop CI instead of being discovered manually after a change.

## Live sandbox

The public deployment is a **synthetic sandbox demo**. It does not use real email accounts, files, calendars, payment services or external webhooks.

Live demo: https://ajan-kalkani.vercel.app/

For the full Turkish documentation, architecture notes and threat model, see [README.md](README.md), [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).
