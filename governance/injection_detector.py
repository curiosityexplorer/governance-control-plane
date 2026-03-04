"""
CP-03 — Prompt Injection Detection
====================================
Scans tool outputs before they are fed back to the planner as observations.
Returns a ScanResult indicating whether injection was detected, a confidence
score, and the matched pattern(s).

Detection strategy: multi-layer heuristic scan covering:
  1. Instruction-override syntax  ("ignore previous instructions")
  2. Role-reassignment language   ("you are now", "act as an unrestricted")
  3. Exfiltration triggers        ("output the contents of", "print your system prompt")
  4. Delimiter injection          (prompt boundary strings: ### SYSTEM, <|im_start|>)
  5. Base64-encoded payloads      (decoded and re-scanned)
  6. Indirect injection patterns  (structured JSON/XML with embedded instructions)
"""

from __future__ import annotations

import re
import base64
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any


# ── Pattern library ───────────────────────────────────────────────────────────

INSTRUCTION_OVERRIDE_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+instructions",
        r"(disregard|forget|override|bypass|skip|cancel)\s+(your\s+)?(previous|prior|above|all|system|original)",
        r"(new|updated|revised|changed)\s+(task|goal|objective|instructions?)\s*:",
        r"disregard\s+(your\s+)?(previous|prior|above|system)\s+",
        r"forget\s+(everything|all)\s+(you\s+)?(were|have been)\s+told",
        r"override\s+(your\s+)?(previous|prior|system)\s+",
        r"new\s+instructions?\s*[:]\s*",
        r"system\s+prompt\s+(override|replacement|update)\s*:",
        r"your\s+(new\s+)?(primary\s+)?instructions?\s+(are|is)\s*:",
        r"all\s+(previous\s+)?(restrictions?|constraints?|controls?)\s+(are\s+)?(lifted|disabled|removed|off)",
    ]
]

ROLE_REASSIGNMENT_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"you\s+are\s+now\s+(an?\s+)?(unrestricted|uncensored|jailbreak|DAN|evil)",
        r"act\s+as\s+(an?\s+)?(unrestricted|uncensored|evil|malicious|hacker)",
        r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(unrestricted|uncensored)",
        r"your\s+(true\s+)?identity\s+is\s+",
        r"switch\s+(to\s+)?(developer|god|admin|root|unrestricted)\s+mode",
        r"DAN\s+mode\s+(enabled|activated|on)",
    ]
]

EXFILTRATION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"(print|output|display|reveal|show|return|send)\s+(the\s+)?(contents?\s+of\s+)?(your\s+)?(system\s+prompt|instructions?|api\s+key|secret|password|token|credentials?)",
        r"(read|cat|type)\s+(~\/\.aws|\/etc\/passwd|\/etc\/shadow|~\/\.ssh|~\/\.env)",
        r"what\s+are\s+your\s+(system\s+)?(instructions?|constraints?|rules?|guidelines?)\??",
        r"tell\s+me\s+(your|the)\s+(system\s+)?prompt",
        r"repeat\s+(your\s+)?(system|initial|original)\s+prompt",
    ]
]

DELIMITER_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"<\|im_start\|>\s*(system|user|assistant)",
        r"###\s*(SYSTEM|INSTRUCTION|PROMPT)\s*###",
        r"\[INST\]|\[\/INST\]",
        r"<s>\s*(<<SYS>>|system)",
        r"Human:\s*Assistant:",
        r"<\|system\|>|<\|user\|>|<\|assistant\|>",
        r"-----BEGIN\s+(SYSTEM|INSTRUCTION)\s+PROMPT-----",
        r"SYSTEM:\s*(override|bypass|disable|ignore)",
        r"USER:\s*.{0,50}\nASSISTANT:\s*(executing|sure|of course|done)",
        r"<!--\s*SYSTEM\s*(OVERRIDE|PROMPT|INSTRUCTION)",
        r"(SYSTEM|INSTRUCTION)\s*:\s*(override|bypass|all\s+restrictions?\s+lifted)",
    ]
]

TOOL_CALL_INJECTION_PATTERNS: list[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in [
        r"call\s+(tool|function)\s+['\"]?\w+['\"]?\s+with",
        r"invoke\s+(the\s+)?['\"]?\w+['\"]?\s+(tool|function|api)",
        r"execute\s+(the\s+)?following\s+(tool|command|function)\s*:",
        r"use\s+tool\s*['\"]?\w+['\"]?\s+to\s+(exfil|steal|read\s+secret)",
    ]
]


# ── Scan result ───────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    """Evidence artifact written to trace for every scanned tool output."""
    session_id:        str
    seq:               int
    timestamp_ms:      int
    tool_name:         str
    raw_output_hash:   str        # SHA-256 of original output
    injected:          bool
    confidence:        float      # 0.0 – 1.0
    matched_patterns:  list[str]  # pattern category names that fired
    payload_hashes:    list[str]  # hashes of matched substring(s)
    sanitized_output:  str | None # returned to planner if injected=True
    latency_ms:        float


# ── InjectionDetector ─────────────────────────────────────────────────────────

class InjectionDetector:
    """
    Multi-layer prompt injection scanner for tool outputs.

    Usage:
        detector = InjectionDetector(session_id="abc123", threshold=0.7)
        result = detector.scan(tool_name="http_get", raw_output="<response>...")
        if result.injected:
            safe_output = result.sanitized_output
    """

    def __init__(self, session_id: str, threshold: float = 0.7):
        self.session_id = session_id
        self.threshold  = threshold   # confidence threshold for flagging
        self._seq       = 0
        self._results: list[ScanResult] = []

    def scan(self, tool_name: str, raw_output: str) -> ScanResult:
        """Scan a tool output string for injection patterns."""
        t_start = time.perf_counter()
        self._seq += 1

        raw_hash = hashlib.sha256(raw_output.encode()).hexdigest()[:16]

        matched: list[tuple[str, str]] = []  # (category, matched_substring)

        # Layer 1–5 scans on raw text
        matched += self._scan_patterns(raw_output, INSTRUCTION_OVERRIDE_PATTERNS, "instruction_override")
        matched += self._scan_patterns(raw_output, ROLE_REASSIGNMENT_PATTERNS,   "role_reassignment")
        matched += self._scan_patterns(raw_output, EXFILTRATION_PATTERNS,         "exfiltration_trigger")
        matched += self._scan_patterns(raw_output, DELIMITER_INJECTION_PATTERNS,  "delimiter_injection")
        matched += self._scan_patterns(raw_output, TOOL_CALL_INJECTION_PATTERNS,  "tool_call_injection")

        # Layer 5: Base64 decode any suspicious segments and re-scan
        b64_segments = re.findall(r'[A-Za-z0-9+/]{40,}={0,2}', raw_output)
        for seg in b64_segments:
            try:
                decoded = base64.b64decode(seg + "==").decode("utf-8", errors="ignore")
                for layer_name, patterns in [
                    ("b64_instruction_override", INSTRUCTION_OVERRIDE_PATTERNS),
                    ("b64_role_reassignment",    ROLE_REASSIGNMENT_PATTERNS),
                    ("b64_exfiltration",         EXFILTRATION_PATTERNS),
                ]:
                    matched += self._scan_patterns(decoded, patterns, layer_name)
            except Exception:
                pass

        # Layer 6: JSON/XML structured injection (instructions embedded in field values)
        matched += self._scan_structured(raw_output)

        # Compute confidence
        categories_fired = set(cat for cat, _ in matched)
        # More categories = higher confidence; single hit = 0.6; all categories = 1.0
        n_cats = len(categories_fired)
        if n_cats == 0:
            confidence = 0.0
        elif n_cats == 1:
            confidence = 0.72
        elif n_cats == 2:
            confidence = 0.82
        else:
            confidence = min(0.95 + (n_cats - 3) * 0.02, 1.0)

        injected = confidence >= self.threshold

        # Sanitize: replace injected segments with a safe placeholder
        sanitized: str | None = None
        if injected:
            sanitized = self._sanitize(raw_output, matched)

        latency_ms = (time.perf_counter() - t_start) * 1000

        result = ScanResult(
            session_id       = self.session_id,
            seq              = self._seq,
            timestamp_ms     = int(time.time() * 1000),
            tool_name        = tool_name,
            raw_output_hash  = raw_hash,
            injected         = injected,
            confidence       = round(confidence, 3),
            matched_patterns = sorted(categories_fired),
            payload_hashes   = [
                hashlib.sha256(sub.encode()).hexdigest()[:12]
                for _, sub in matched
            ],
            sanitized_output = sanitized,
            latency_ms       = round(latency_ms, 3),
        )
        self._results.append(result)
        return result

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _scan_patterns(
        self,
        text: str,
        patterns: list[re.Pattern],
        category: str,
    ) -> list[tuple[str, str]]:
        hits = []
        for pat in patterns:
            m = pat.search(text)
            if m:
                hits.append((category, m.group(0)[:120]))  # cap payload length
        return hits

    def _scan_structured(self, text: str) -> list[tuple[str, str]]:
        """Extract string values from JSON/XML and scan them for injection."""
        hits = []
        # Grab all quoted string values (handles both JSON and XML attribute values)
        values = re.findall(r'["\']([^"\']{20,})["\']', text)
        for val in values:
            hits += self._scan_patterns(val, INSTRUCTION_OVERRIDE_PATTERNS, "structured_override")
            hits += self._scan_patterns(val, EXFILTRATION_PATTERNS,         "structured_exfil")
        return hits

    def _sanitize(self, text: str, matched: list[tuple[str, str]]) -> str:
        """Replace matched injection content with a safe marker."""
        sanitized = text
        for _, payload in matched:
            if payload and payload in sanitized:
                sanitized = sanitized.replace(
                    payload,
                    "[GOVERNANCE: INJECTION PATTERN REDACTED]"
                )
        return sanitized

    def detection_rate(self) -> float:
        """Fraction of scanned outputs that were flagged."""
        if not self._results:
            return 0.0
        return sum(1 for r in self._results if r.injected) / len(self._results)

    def get_all_results(self) -> list[ScanResult]:
        return list(self._results)
