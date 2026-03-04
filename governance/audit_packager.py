"""
CP-10 — Audit Artifact Packager
=================================
Assembles a tamper-evident audit package containing:
  - All trace JSONL files for the session
  - A snapshot of the active policy configuration
  - The human override log
  - The evaluation harness report
  - A manifest with SHA-256 checksums of every included file

Package format: ZIP archive with a signed manifest.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import zipfile
from pathlib import Path


class AuditPackager:

    def __init__(self, session_id: str, results_dir: str = "./results"):
        self.session_id  = session_id
        self.results_dir = Path(results_dir)

    def build_package(
        self,
        trace_paths:      list[str],
        escalation_records: list[dict],
        policy_snapshot:  dict,
        eval_report:      dict | None = None,
        out_dir:          str = "./results/audit_packages",
    ) -> str:
        """
        Build a tamper-evident audit ZIP package.
        Returns the path to the created package.
        """
        t_start = time.perf_counter()
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        pkg_path = f"{out_dir}/{self.session_id}_audit.zip"

        manifest = {
            "session_id":    self.session_id,
            "created_ms":    int(time.time() * 1000),
            "package_type":  "governance_audit_v1",
            "files":         [],
        }

        with zipfile.ZipFile(pkg_path, "w", zipfile.ZIP_DEFLATED) as zf:

            # 1. Trace files
            for tp in trace_paths:
                if os.path.exists(tp):
                    checksum = self._file_sha256(tp)
                    arcname  = f"traces/{Path(tp).name}"
                    zf.write(tp, arcname)
                    manifest["files"].append({"name": arcname, "sha256": checksum})

            # 2. Policy snapshot
            policy_json = json.dumps(policy_snapshot, indent=2, default=str).encode()
            zf.writestr("policy/policy_snapshot.json", policy_json)
            manifest["files"].append({
                "name": "policy/policy_snapshot.json",
                "sha256": hashlib.sha256(policy_json).hexdigest(),
            })

            # 3. Human override log
            override_json = json.dumps(escalation_records, indent=2, default=str).encode()
            zf.writestr("overrides/human_override_log.json", override_json)
            manifest["files"].append({
                "name": "overrides/human_override_log.json",
                "sha256": hashlib.sha256(override_json).hexdigest(),
            })

            # 4. Evaluation report (if provided)
            if eval_report:
                eval_json = json.dumps(eval_report, indent=2, default=str).encode()
                zf.writestr("eval/evaluation_report.json", eval_json)
                manifest["files"].append({
                    "name": "eval/evaluation_report.json",
                    "sha256": hashlib.sha256(eval_json).hexdigest(),
                })

            # 5. Write manifest last
            manifest["build_latency_ms"] = round((time.perf_counter() - t_start) * 1000, 2)
            manifest_bytes = json.dumps(manifest, indent=2).encode()
            manifest["manifest_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
            zf.writestr("MANIFEST.json", json.dumps(manifest, indent=2))

        return pkg_path

    @staticmethod
    def verify_package(pkg_path: str) -> dict:
        """
        Verify the integrity of an audit package.
        Returns {"valid": bool, "errors": list[str]}.
        """
        errors = []
        with zipfile.ZipFile(pkg_path, "r") as zf:
            try:
                manifest = json.loads(zf.read("MANIFEST.json"))
            except Exception as e:
                return {"valid": False, "errors": [f"Cannot read manifest: {e}"]}

            for entry in manifest.get("files", []):
                try:
                    data = zf.read(entry["name"])
                    actual = hashlib.sha256(data).hexdigest()
                    if actual != entry["sha256"]:
                        errors.append(f"Checksum mismatch: {entry['name']}")
                except KeyError:
                    errors.append(f"Missing file: {entry['name']}")

        return {"valid": len(errors) == 0, "errors": errors}

    @staticmethod
    def _file_sha256(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
