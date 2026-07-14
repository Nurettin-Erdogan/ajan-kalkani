"""Ajan Kalkanı veri modelleri."""

from __future__ import annotations

from enum import Enum
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
    tool: str
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
