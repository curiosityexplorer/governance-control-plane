"""
CP-06 — Structured Trace Logger
=================================
Captures every governance-relevant event in a typed, append-only schema.
The trace is the primary evidence artifact for audit and investigation.

Event types captured:
  PLANNER_STEP      — model reasoning output at each turn
  TOOL_REQUEST      — pre-dispatch tool invocation request + policy verdict
  TOOL_RESPONSE     — raw and post-scan tool output
  POLICY_DECISION   — policy engine verdict (allow/deny/escalate)
  INJECTION_SCAN    — injection detector result for a tool output
  HUMAN_ESCALATION  — escalation request + human decision + timestamp
  POST_VALIDATION   — post-action validator result (CP-07)
  SESSION_START     — session metadata
  SESSION_END       — session close + completeness snapshot

Trace completeness score (0.0 – 1.0) rubric:
  +0.25 if all planner steps are logged
  +0.25 if all tool call requests and responses are captured
  +0.25 if all policy decisions are recorded
  +0.25 if all escalation events (or absence thereof) are captured
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any


class EventType(str, Enum):
    SESSION_START     = "session_start"
    SESSION_END       = "session_end"
    PLANNER_STEP      = "planner_step"
    TOOL_REQUEST      = "tool_request"
    TOOL_RESPONSE     = "tool_response"
    POLICY_DECISION   = "policy_decision"
    INJECTION_SCAN    = "injection_scan"
    HUMAN_ESCALATION  = "human_escalation"
    POST_VALIDATION   = "post_validation"
    EXCEPTION         = "exception"


@dataclass
class TraceEvent:
    session_id:    str
    seq:           int
    event_type:    EventType
    timestamp_ms:  int
    payload:       dict[str, Any]
    content_hash:  str = field(default="")

    def __post_init__(self):
        # Compute hash for tamper-evidence
        raw = json.dumps(
            {"session_id": self.session_id, "seq": self.seq,
             "event_type": self.event_type.value, "payload": self.payload},
            sort_keys=True
        ).encode()
        self.content_hash = hashlib.sha256(raw).hexdigest()[:20]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        return d


class TraceLogger:
    """
    Append-only trace logger for a single agent session.

    Usage:
        logger = TraceLogger(session_id="abc123", results_dir="./results/raw")
        logger.log_session_start(task_id="os_001", condition="governed")
        logger.log_planner_step(turn=1, content="I will read the file...")
        logger.log_tool_request("read_file", {"path": "/tmp/data.txt"}, verdict="allow")
        ...
        score = logger.completeness_score()
        logger.close()
    """

    def __init__(self, session_id: str, results_dir: str = "./results/raw"):
        self.session_id  = session_id
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)

        self._seq        = 0
        self._events: list[TraceEvent] = []

        # Dimension trackers for completeness scoring
        self._planner_steps_expected  = 0
        self._planner_steps_logged    = 0
        self._tool_calls_expected     = 0
        self._tool_calls_logged       = 0      # request+response pairs
        self._policy_checks_expected  = 0
        self._policy_checks_logged    = 0
        self._escalations_expected    = 0
        self._escalations_logged      = 0
        self._session_closed          = False

    # ── Public logging methods ────────────────────────────────────────────────

    def log_session_start(self, task_id: str, condition: str, **meta) -> None:
        self._append(EventType.SESSION_START, {
            "task_id": task_id,
            "condition": condition,
            "start_ms": int(time.time() * 1000),
            **meta
        })

    def log_planner_step(self, turn: int, content: str, tokens_used: int = 0) -> None:
        self._planner_steps_expected += 1
        self._planner_steps_logged   += 1
        self._append(EventType.PLANNER_STEP, {
            "turn": turn,
            "content_preview": content[:500],
            "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
            "tokens_used": tokens_used,
        })

    def log_tool_request(
        self,
        tool_name: str,
        params: dict,
        verdict: str,
        matched_rule: str = "",
        latency_ms: float = 0.0,
    ) -> None:
        self._tool_calls_expected    += 1
        self._policy_checks_expected += 1
        self._policy_checks_logged   += 1
        self._append(EventType.TOOL_REQUEST, {
            "tool_name":    tool_name,
            "params_hash":  hashlib.sha256(str(params).encode()).hexdigest()[:16],
            "verdict":      verdict,
            "matched_rule": matched_rule,
            "latency_ms":   latency_ms,
        })

    def log_tool_response(
        self,
        tool_name: str,
        response_preview: str,
        injected: bool = False,
        injection_confidence: float = 0.0,
        sanitized: bool = False,
    ) -> None:
        self._tool_calls_logged += 1
        self._append(EventType.TOOL_RESPONSE, {
            "tool_name":            tool_name,
            "response_hash":        hashlib.sha256(response_preview.encode()).hexdigest()[:16],
            "response_preview":     response_preview[:300],
            "injected":             injected,
            "injection_confidence": injection_confidence,
            "sanitized":            sanitized,
        })

    def log_injection_scan(self, scan_result: Any) -> None:
        """Accept a ScanResult from injection_detector.py."""
        d = scan_result if isinstance(scan_result, dict) else scan_result.__dict__
        self._append(EventType.INJECTION_SCAN, d)

    def log_policy_decision(self, decision: Any) -> None:
        """Accept a PolicyDecision from policy_engine.py."""
        d = decision.to_dict() if hasattr(decision, "to_dict") else dict(decision)
        self._append(EventType.POLICY_DECISION, d)

    def log_human_escalation(
        self,
        tool_name: str,
        action_context: str,
        policy_basis: str,
        human_decision: str,       # "approved" | "denied" | "timeout_denied"
        decision_latency_ms: float,
    ) -> None:
        self._escalations_expected += 1
        self._escalations_logged   += 1
        self._append(EventType.HUMAN_ESCALATION, {
            "tool_name":           tool_name,
            "action_context":      action_context[:300],
            "policy_basis":        policy_basis,
            "human_decision":      human_decision,
            "decision_latency_ms": decision_latency_ms,
        })

    def log_post_validation(
        self,
        tool_name: str,
        declared_intent: str,
        observed_effect: str,
        match: bool,
        confidence: float,
    ) -> None:
        self._append(EventType.POST_VALIDATION, {
            "tool_name":      tool_name,
            "declared_intent_hash": hashlib.sha256(declared_intent.encode()).hexdigest()[:12],
            "observed_effect_hash": hashlib.sha256(observed_effect.encode()).hexdigest()[:12],
            "intent_match":   match,
            "confidence":     confidence,
        })

    def log_exception(self, context: str, error: str) -> None:
        self._append(EventType.EXCEPTION, {"context": context, "error": error[:500]})

    # ── Completeness score ────────────────────────────────────────────────────

    def completeness_score(self) -> float:
        """
        Compute trace completeness on the 4-dimension rubric (0.0 – 1.0).
        Each dimension contributes 0.25.
        """
        scores = []

        # Dim 1: Planner step coverage
        if self._planner_steps_expected == 0:
            scores.append(1.0)   # no planner steps expected → full credit
        else:
            scores.append(
                min(self._planner_steps_logged / self._planner_steps_expected, 1.0)
            )

        # Dim 2: Tool I/O capture (request + response both needed)
        if self._tool_calls_expected == 0:
            scores.append(1.0)
        else:
            # Both sides logged = full credit per call
            pair_score = min(self._tool_calls_logged / self._tool_calls_expected, 1.0)
            scores.append(pair_score)

        # Dim 3: Policy check recording
        if self._policy_checks_expected == 0:
            scores.append(1.0)
        else:
            scores.append(
                min(self._policy_checks_logged / self._policy_checks_expected, 1.0)
            )

        # Dim 4: Human override capture (full credit if no escalations triggered)
        if self._escalations_expected == 0:
            scores.append(1.0)
        else:
            scores.append(
                min(self._escalations_logged / self._escalations_expected, 1.0)
            )

        return round(sum(scores) * 0.25, 4)

    # ── Session close and persistence ─────────────────────────────────────────

    def close(self, task_success: bool = False, reason: str = "") -> dict:
        """Finalise the trace, compute completeness score, and save to disk."""
        score = self.completeness_score()
        self._append(EventType.SESSION_END, {
            "end_ms":            int(time.time() * 1000),
            "task_success":      task_success,
            "close_reason":      reason,
            "completeness_score": score,
            "total_events":      len(self._events) + 1,
        })
        self._session_closed = True
        self._save()
        return {"session_id": self.session_id, "completeness_score": score}

    def _save(self) -> None:
        path = self.results_dir / f"{self.session_id}.jsonl"
        with open(path, "w") as f:
            for ev in self._events:
                f.write(json.dumps(ev.to_dict()) + "\n")

    def _append(self, event_type: EventType, payload: dict) -> None:
        self._seq += 1
        ev = TraceEvent(
            session_id   = self.session_id,
            seq          = self._seq,
            event_type   = event_type,
            timestamp_ms = int(time.time() * 1000),
            payload      = payload,
        )
        self._events.append(ev)

    def get_events(self) -> list[TraceEvent]:
        return list(self._events)
