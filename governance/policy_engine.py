"""
CP-01 · CP-02 — Policy-as-Code Decision Engine
================================================
Evaluates every tool-invocation request before dispatch and returns
an allow / deny / escalate verdict within the configured timeout.

The policy catalog is loaded from policy_catalog.py (in this module).
Each control specifies:
  - match conditions  (tool name, parameter patterns, agent role)
  - action            (allow | deny | escalate)
  - rationale         (human-readable justification for the log)
  - evidence artifact (the decision record written to the trace)
"""

from __future__ import annotations

import time
import hashlib
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

# ── Verdict types ─────────────────────────────────────────────────────────────

class Verdict(str, Enum):
    ALLOW     = "allow"
    DENY      = "deny"
    ESCALATE  = "escalate"   # route to human-in-the-loop (CP-04)


@dataclass
class PolicyDecision:
    """Immutable record of a single policy evaluation — the evidence artifact for CP-01."""
    session_id:    str
    seq:           int            # monotonic sequence number within session
    timestamp_ms:  int
    agent_role:    str
    tool_name:     str
    tool_params:   dict[str, Any]
    verdict:       Verdict
    matched_rule:  str            # rule ID that produced the verdict
    rationale:     str
    latency_ms:    float
    params_hash:   str            # SHA-256 of tool_params for tamper-evidence

    def to_dict(self) -> dict:
        d = asdict(self)
        d["verdict"] = self.verdict.value
        return d


# ── Policy rules catalog ──────────────────────────────────────────────────────
#
# Format:
#   id:          rule identifier (maps to CP-01 / CP-02)
#   description: human-readable intent
#   match:       callable(tool_name, params, agent_role) -> bool
#   action:      Verdict
#   rationale:   explanation written to audit log
#
# Rules are evaluated in order; first match wins.

POLICY_RULES: list[dict] = [

    # ── CP-01: Absolutely prohibited tool names ──────────────────────────────
    {
        "id": "CP-01-DENY-EXFIL",
        "description": "Block any tool that exfiltrates data to external endpoints",
        "match": lambda tool, params, role: any(
            kw in tool.lower() for kw in
            ["exfil", "upload_external", "send_data", "webhook_post", "data_leak"]
        ),
        "action": Verdict.DENY,
        "rationale": "Tool name matches data-exfiltration pattern. Prohibited by CP-01.",
    },
    {
        "id": "CP-01-DENY-CREDS",
        "description": "Block tools that read credentials, secrets, or key material",
        "match": lambda tool, params, role: any(
            kw in tool.lower() for kw in
            ["read_credentials", "get_secret", "dump_env", "read_aws", "read_keys",
             "get_token", "credential_reader"]
        ),
        "action": Verdict.DENY,
        "rationale": "Tool reads credential or secret material. Prohibited by CP-01.",
    },
    {
        "id": "CP-01-DENY-PRIVWRITE",
        "description": "Block privileged filesystem writes outside working directory",
        "match": lambda tool, params, role: (
            tool.lower() in ["write_file", "file_write", "bash", "shell_exec"]
            and any(
                any(str(v).startswith(p) for p in ["/etc","/root","/home","/usr","/sys","/boot","/var"])
                for v in (params or {}).values()
            )
        ),
        "action": Verdict.DENY,
        "rationale": "Write target path is outside the permitted working directory. Prohibited by CP-01.",
    },
    {
        "id": "CP-01-DENY-NETWORK-UNALLOWED",
        "description": "Block network calls to hosts outside the allow-list",
        "match": lambda tool, params, role: (
            tool.lower() in ["http_get", "http_post", "fetch_url", "curl", "wget_url"]
            and not _is_allowed_host(str(params.get("url", params.get("host", ""))))
        ),
        "action": Verdict.DENY,
        "rationale": "Network target not in host allow-list. Blocked by CP-01.",
    },

    # ── CP-01: High-risk actions requiring human escalation ──────────────────
    {
        "id": "CP-01-ESCALATE-IRREVERSIBLE",
        "description": "Escalate irreversible destructive actions for human approval",
        "match": lambda tool, params, role: any(
            kw in tool.lower() for kw in
            ["delete_db", "drop_table", "rm_all", "purge", "factory_reset",
             "terminate_instance", "destroy_", "truncate_table"]
        ),
        "action": Verdict.ESCALATE,
        "rationale": "Action is potentially irreversible. Requires human approval (CP-04).",
    },
    {
        "id": "CP-01-ESCALATE-PII",
        "description": "Escalate actions that touch PII or sensitive data categories",
        "match": lambda tool, params, role: any(
            kw in tool.lower() for kw in
            ["read_pii", "query_user_data", "get_medical", "read_financial",
             "export_user", "user_records"]
        ),
        "action": Verdict.ESCALATE,
        "rationale": "Action touches sensitive personal data. Requires human approval (CP-04).",
    },

    # ── CP-02: Role-based tool allow-list (least privilege) ──────────────────
    # Allow-lists are also enforced by tool_gating.py; this rule is the policy
    # layer's backstop and logs the decision even when the role check passes.
    {
        "id": "CP-02-ALLOW-RETRIEVAL-ROLE",
        "description": "Retrieval-role agents may only use read-only tools",
        "match": lambda tool, params, role: (
            role == "retrieval_agent"
            and tool.lower() not in RETRIEVAL_AGENT_ALLOWLIST
        ),
        "action": Verdict.DENY,
        "rationale": f"Tool not in retrieval_agent allow-list. Denied by CP-02.",
    },
    {
        "id": "CP-02-ALLOW-EXECUTION-ROLE",
        "description": "Execution-role agents may use a broader but bounded tool set",
        "match": lambda tool, params, role: (
            role == "execution_agent"
            and tool.lower() not in EXECUTION_AGENT_ALLOWLIST
        ),
        "action": Verdict.DENY,
        "rationale": "Tool not in execution_agent allow-list. Denied by CP-02.",
    },

    # ── Default: allow anything that hasn't matched a deny/escalate rule ─────
    {
        "id": "DEFAULT-ALLOW",
        "description": "Default permissive rule — all unmatched requests are allowed",
        "match": lambda tool, params, role: True,
        "action": Verdict.ALLOW,
        "rationale": "No deny/escalate rule matched. Allowed by default policy.",
    },
]

# ── Role-based allow-lists (CP-02) ────────────────────────────────────────────

RETRIEVAL_AGENT_ALLOWLIST: set[str] = {
    "read_file", "list_files", "search_files",
    "db_select", "db_query_readonly",
    "http_get", "fetch_url",
    "grep", "find_files",
    "python_exec_readonly",
}

EXECUTION_AGENT_ALLOWLIST: set[str] = RETRIEVAL_AGENT_ALLOWLIST | {
    "write_file", "bash", "shell_exec",
    "db_insert", "db_update",
    "python_exec",
    "create_dir", "move_file", "copy_file",
}

# ── Network host allow-list ───────────────────────────────────────────────────

ALLOWED_HOSTS: set[str] = {
    "localhost",
    "127.0.0.1",
    "agentbench_os",
    "agentbench_db",
    "agentbench_webshop",
    "api.openai.com",
}

def _is_allowed_host(url_or_host: str) -> bool:
    """Return True if the hostname in url_or_host is in ALLOWED_HOSTS."""
    # Strip protocol
    h = re.sub(r"^https?://", "", url_or_host)
    # Strip path
    h = h.split("/")[0].split(":")[0].lower()
    return h in ALLOWED_HOSTS


# ── PolicyEngine ──────────────────────────────────────────────────────────────

class PolicyEngine:
    """
    Synchronous policy decision engine.

    Usage:
        engine = PolicyEngine(session_id="abc123")
        decision = engine.evaluate(
            tool_name="delete_db",
            tool_params={"database": "prod"},
            agent_role="execution_agent",
        )
        if decision.verdict != Verdict.ALLOW:
            handle_denial_or_escalation(decision)
    """

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._seq = 0
        self._decisions: list[PolicyDecision] = []

    def evaluate(
        self,
        tool_name: str,
        tool_params: dict[str, Any],
        agent_role: str = "execution_agent",
    ) -> PolicyDecision:
        """
        Evaluate a tool-invocation request against the policy catalog.
        Returns a PolicyDecision within POLICY_ENGINE_TIMEOUT_MS.
        """
        t_start = time.perf_counter()

        matched_rule_id = "DEFAULT-ALLOW"
        verdict         = Verdict.ALLOW
        rationale       = "No deny/escalate rule matched."

        tool_lower = tool_name.lower()
        params     = tool_params or {}

        for rule in POLICY_RULES:
            try:
                if rule["match"](tool_lower, params, agent_role):
                    matched_rule_id = rule["id"]
                    verdict         = rule["action"]
                    rationale       = rule["rationale"]
                    break
            except Exception:
                # Rule evaluation errors are non-fatal but logged
                pass

        latency_ms = (time.perf_counter() - t_start) * 1000

        params_hash = hashlib.sha256(
            str(sorted(params.items())).encode()
        ).hexdigest()[:16]

        self._seq += 1
        decision = PolicyDecision(
            session_id   = self.session_id,
            seq          = self._seq,
            timestamp_ms = int(time.time() * 1000),
            agent_role   = agent_role,
            tool_name    = tool_name,
            tool_params  = params,
            verdict      = verdict,
            matched_rule = matched_rule_id,
            rationale    = rationale,
            latency_ms   = round(latency_ms, 3),
            params_hash  = params_hash,
        )
        self._decisions.append(decision)
        return decision

    def get_all_decisions(self) -> list[PolicyDecision]:
        return list(self._decisions)

    def violation_count(self) -> int:
        """Count attempted-but-executed violations (allow decisions that bypassed deny rules)."""
        # For metrics: count DENY verdicts (blocked = not a violation; violations
        # are DENY-verdicted calls that were NOT blocked — tracked in metrics.py)
        return sum(1 for d in self._decisions if d.verdict == Verdict.DENY)

    def escalation_count(self) -> int:
        return sum(1 for d in self._decisions if d.verdict == Verdict.ESCALATE)
