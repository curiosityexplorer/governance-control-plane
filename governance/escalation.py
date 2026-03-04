"""
CP-04 — Human-in-the-Loop (HITL) Escalation Manager
=====================================================
Routes high-risk tool-invocation requests to a human operator
approval queue before execution proceeds.

In HITL_MODE=auto  (batch experiments): all escalations are
auto-approved after logging, recording the decision latency as ~0 ms.
This lets the full experiment run unattended while still measuring
which actions triggered escalation and at what rate.

In HITL_MODE=interactive: the operator is prompted at the terminal
and has HITL_TIMEOUT_SECONDS to respond; timeout → auto-deny.

The escalation log is a required component of the audit package (CP-10).
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from enum import Enum


class EscalationDecision(str, Enum):
    APPROVED        = "approved"
    DENIED          = "denied"
    TIMEOUT_DENIED  = "timeout_denied"


@dataclass
class EscalationRecord:
    session_id:          str
    seq:                 int
    timestamp_ms:        int
    tool_name:           str
    agent_role:          str
    action_context:      str     # agent's stated rationale
    policy_basis:        str     # which rule triggered escalation
    decision:            EscalationDecision
    decision_latency_ms: float
    operator_note:       str = ""

    def to_dict(self) -> dict:
        return {
            "session_id":          self.session_id,
            "seq":                 self.seq,
            "timestamp_ms":        self.timestamp_ms,
            "tool_name":           self.tool_name,
            "agent_role":          self.agent_role,
            "action_context":      self.action_context,
            "policy_basis":        self.policy_basis,
            "decision":            self.decision.value,
            "decision_latency_ms": self.decision_latency_ms,
            "operator_note":       self.operator_note,
        }


class EscalationManager:
    """
    Manages the HITL escalation queue for a session.

    Usage:
        mgr = EscalationManager(session_id="abc123")
        record = mgr.request_approval(
            tool_name="delete_db",
            agent_role="execution_agent",
            action_context="Agent plans to delete the prod database",
            policy_basis="CP-01-ESCALATE-IRREVERSIBLE",
        )
        if record.decision == EscalationDecision.APPROVED:
            proceed_with_tool_call()
    """

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._mode      = os.getenv("HITL_MODE", "auto").lower()
        self._timeout   = int(os.getenv("HITL_TIMEOUT_SECONDS", "30"))
        self._seq       = 0
        self._records: list[EscalationRecord] = []

    def request_approval(
        self,
        tool_name:      str,
        agent_role:     str,
        action_context: str,
        policy_basis:   str,
    ) -> EscalationRecord:
        """
        Request human approval for a high-risk tool invocation.
        Returns an EscalationRecord with the decision.
        """
        self._seq += 1
        t_start = time.perf_counter()

        if self._mode == "interactive":
            decision, note = self._interactive_prompt(
                tool_name, action_context, policy_basis
            )
        else:
            # Auto mode: approve and log (for batch experiments)
            decision = EscalationDecision.APPROVED
            note     = "auto-approved (batch mode)"

        latency_ms = (time.perf_counter() - t_start) * 1000

        record = EscalationRecord(
            session_id          = self.session_id,
            seq                 = self._seq,
            timestamp_ms        = int(time.time() * 1000),
            tool_name           = tool_name,
            agent_role          = agent_role,
            action_context      = action_context[:500],
            policy_basis        = policy_basis,
            decision            = decision,
            decision_latency_ms = round(latency_ms, 2),
            operator_note       = note,
        )
        self._records.append(record)
        return record

    # ── Interactive prompt (terminal) ─────────────────────────────────────────

    def _interactive_prompt(
        self,
        tool_name:      str,
        action_context: str,
        policy_basis:   str,
    ) -> tuple[EscalationDecision, str]:

        print("\n" + "="*60)
        print("⚠️  HUMAN APPROVAL REQUIRED")
        print("="*60)
        print(f"  Tool:          {tool_name}")
        print(f"  Policy basis:  {policy_basis}")
        print(f"  Context:       {action_context[:300]}")
        print(f"  Timeout:       {self._timeout}s")
        print("-"*60)

        import signal

        def _timeout_handler(signum, frame):
            raise TimeoutError

        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(self._timeout)

        try:
            response = input("  Approve? [y/N/note]: ").strip().lower()
            signal.alarm(0)
        except (TimeoutError, EOFError):
            signal.alarm(0)
            print(f"  ⏱ Timeout — auto-denied.")
            return EscalationDecision.TIMEOUT_DENIED, "operator did not respond within timeout"

        if response.startswith("y"):
            return EscalationDecision.APPROVED, response
        return EscalationDecision.DENIED, response

    # ── Metrics ───────────────────────────────────────────────────────────────

    def escalation_count(self) -> int:
        return len(self._records)

    def approval_rate(self) -> float:
        if not self._records:
            return 0.0
        approved = sum(1 for r in self._records
                       if r.decision == EscalationDecision.APPROVED)
        return approved / len(self._records)

    def mean_decision_latency_ms(self) -> float:
        if not self._records:
            return 0.0
        return sum(r.decision_latency_ms for r in self._records) / len(self._records)

    def get_all_records(self) -> list[EscalationRecord]:
        return list(self._records)
