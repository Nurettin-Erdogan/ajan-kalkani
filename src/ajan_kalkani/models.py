"""Ajan Kalkanı veri modelleri."""

from __future__ import annotations

from enum import Enum
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class RunMode(str, Enum):
    UNPROTECTED = "unprotected"
    GUARDED = "guarded"


class IntentContract(BaseModel):
    task: str
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    approval_required: list[str] = Field(default_factory=list)


class ToolCall(BaseModel):
    tool: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    arguments: dict[str, Any] = Field(default_factory=dict)
    origin: str = "user"
    data_labels: set[str] = Field(default_factory=set)


class PolicyDecision(BaseModel):
    allowed: bool
    requires_approval: bool = False
    reason: str
    rule_id: str
    risk: Literal["low", "medium", "high", "critical"] = "low"


class TraceEvent(BaseModel):
    step: int
    actor: Literal["agent", "gateway", "tool", "system"]
    action: str
    decision: Literal["observed", "allowed", "blocked", "executed", "error"]
    risk: Literal["low", "medium", "high", "critical"]
    title: str
    detail: str
    input: dict[str, Any] | None = None
    output: dict[str, Any] | None = None
    rule_id: str | None = None


class RunMetrics(BaseModel):
    attempted_calls: int = 0
    executed_calls: int = 0
    blocked_calls: int = 0
    execution_errors: int = 0
    sensitive_reads: int = 0
    external_writes: int = 0
    approval_requests: int = 0


class RunRequest(BaseModel):
    scenario_id: str
    mode: RunMode


class ScenarioSummary(BaseModel):
    id: str
    name: str
    description: str
    task: str
    category: str


class RunResult(BaseModel):
    id: str
    scenario_id: str
    scenario_name: str
    mode: RunMode
    status: Literal["completed", "protected", "compromised", "failed"]
    task_success: bool
    attack_success: bool
    duration_ms: int
    summary: str
    contract: IntentContract
    events: list[TraceEvent]
    metrics: RunMetrics


class AuditRunSummary(BaseModel):
    id: str
    created_at: str
    scenario_id: str
    scenario_name: str
    mode: RunMode
    status: Literal["completed", "protected", "compromised", "failed"]
    task_success: bool
    attack_success: bool


class AuditEvaluationSummary(BaseModel):
    id: str
    created_at: str
    passed: bool


class AuditIntegrityReport(BaseModel):
    valid: bool
    run_count: int
    evaluation_count: int
    broken_record_ids: list[str] = Field(default_factory=list)


class ContractFinding(BaseModel):
    code: str
    severity: Literal["info", "warning", "critical"]
    message: str
    patterns: list[str] = Field(default_factory=list)


class PolicyEvaluationRequest(BaseModel):
    contract: IntentContract
    calls: list[ToolCall] = Field(min_length=1, max_length=50)
    mode: RunMode = RunMode.GUARDED


class PolicyEvaluationItem(BaseModel):
    position: int = Field(ge=1)
    tool: str
    origin: str
    data_labels: list[str]
    decision: PolicyDecision


class PolicyEvaluationSummary(BaseModel):
    total_calls: int
    allowed_calls: int
    blocked_calls: int
    approval_requests: int
    highest_risk: Literal["low", "medium", "high", "critical"]


class PolicyEvaluationResponse(BaseModel):
    mode: RunMode
    summary: PolicyEvaluationSummary
    findings: list[ContractFinding]
    results: list[PolicyEvaluationItem]


class GatewaySessionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    contract: IntentContract
    ttl_minutes: int = Field(default=60, ge=1, le=1440)


class GatewaySessionSummary(BaseModel):
    id: str
    name: str
    created_at: datetime
    expires_at: datetime
    status: Literal["active", "expired"]
    contract_hash: str
    decision_count: int = Field(default=0, ge=0)


class GatewaySessionDetail(GatewaySessionSummary):
    contract: IntentContract


class GatewayAuthorizationRequest(BaseModel):
    call: ToolCall


class GatewayDecisionRecord(BaseModel):
    session_id: str
    sequence: int = Field(ge=1)
    created_at: datetime
    tool: str
    origin: str
    data_labels: list[str]
    request_hash: str
    decision: PolicyDecision
