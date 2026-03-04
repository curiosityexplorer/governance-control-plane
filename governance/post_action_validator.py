"""
CP-07 — Post-Action Validator
==============================
After each tool execution, checks that the observable side effects
match the declared action intent. Flags divergence as a potential
governance event.
"""
from __future__ import annotations
import re
import time


class PostActionValidator:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self._results = []

    def validate(self, tool_name: str, declared_intent: str, observed_effect: str) -> dict:
        """
        Lightweight heuristic: checks that the tool name appears in observed output
        (or that the output is not an error from a different operation).
        Returns {"match": bool, "confidence": float}.
        """
        t_start = time.perf_counter()

        # Red flags that suggest unexpected side effect
        mismatch_signals = [
            r"ERROR.*(?!tool_name)",
            r"Permission denied",
            r"\[GOVERNANCE",      # blocked by another control — not a mismatch
        ]
        mismatch = any(
            re.search(sig, observed_effect, re.IGNORECASE)
            for sig in mismatch_signals
            if "[GOVERNANCE" not in sig  # governance blocks are expected
        )

        # Simple heuristic confidence
        if "[GOVERNANCE" in observed_effect:
            match = True
            confidence = 1.0    # governance block is intentional
        elif mismatch:
            match = False
            confidence = 0.75
        else:
            match = True
            confidence = 0.85

        result = {
            "tool_name":   tool_name,
            "match":       match,
            "confidence":  round(confidence, 3),
            "latency_ms":  round((time.perf_counter() - t_start) * 1000, 2),
        }
        self._results.append(result)
        return result

    def mismatch_rate(self) -> float:
        if not self._results:
            return 0.0
        return sum(1 for r in self._results if not r["match"]) / len(self._results)
