"""
AgentBench Adapter
===================
Loads tasks from the three AgentBench Docker environments and provides
a uniform interface for the harness to run them.

Each environment exposes a REST API (from AgentBench's task server):
  GET  /tasks          — list available task IDs
  POST /tasks/{id}/start  — initialize a task, returns initial observation
  POST /tasks/{id}/step   — submit an action, returns (observation, reward, done, info)
  POST /tasks/{id}/reset  — reset to initial state

Task domains used in the paper:
  os_interaction  — Bash shell tasks (file I/O, process management, scripting)
  dbbench         — SQL database manipulation tasks
  webshop         — Multi-step web shopping tasks (injection surface)
"""

from __future__ import annotations

import os
import time
import requests
from dataclasses import dataclass
from typing import Any, Iterator


# ── Task definition ────────────────────────────────────────────────────────────

@dataclass
class AgentBenchTask:
    task_id:     str
    domain:      str       # "os" | "db" | "webshop"
    description: str       # natural language task description shown to agent
    host:        str
    port:        int

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"


@dataclass
class StepResult:
    observation: str
    reward:      float     # 0.0 or 1.0 for most AgentBench tasks
    done:        bool
    info:        dict[str, Any]


# ── AgentBench Adapter ─────────────────────────────────────────────────────────

class AgentBenchAdapter:
    """
    Wraps the AgentBench HTTP task server.

    Usage:
        adapter = AgentBenchAdapter()
        tasks = list(adapter.load_tasks(domains=["os", "db"]))
        for task in tasks:
            obs = adapter.start_task(task)
            result = adapter.step(task, "ls -la")
            adapter.reset(task)
    """

    DOMAIN_CONFIG: dict[str, dict] = {
        "os": {
            "env_var_host": "AGENTBENCH_OS_HOST",
            "env_var_port": "AGENTBENCH_OS_PORT",
            "default_host": "localhost",
            "default_port": 5001,
            "task_count":   20,    # tasks used from this domain
        },
        "db": {
            "env_var_host": "AGENTBENCH_DB_HOST",
            "env_var_port": "AGENTBENCH_DB_PORT",
            "default_host": "localhost",
            "default_port": 5002,
            "task_count":   15,
        },
        "webshop": {
            "env_var_host": "AGENTBENCH_WEB_HOST",
            "env_var_port": "AGENTBENCH_WEB_PORT",
            "default_host": "localhost",
            "default_port": 5003,
            "task_count":   10,
        },
    }

    def __init__(self, timeout_s: int = 30):
        self._timeout = timeout_s
        self._sessions: dict[str, str] = {}  # task_id -> session_token

    # ── Task loading ──────────────────────────────────────────────────────────

    def load_tasks(
        self,
        domains: list[str] | None = None,
        max_per_domain: int | None = None,
    ) -> Iterator[AgentBenchTask]:
        """Yield AgentBenchTask objects for the specified domains."""
        domains = domains or ["os", "db", "webshop"]

        for domain in domains:
            cfg  = self.DOMAIN_CONFIG[domain]
            host = os.getenv(cfg["env_var_host"], cfg["default_host"])
            port = int(os.getenv(cfg["env_var_port"], cfg["default_port"]))
            limit = max_per_domain or cfg["task_count"]

            try:
                resp = requests.get(
                    f"http://{host}:{port}/tasks",
                    timeout=self._timeout
                )
                resp.raise_for_status()
                task_list = resp.json()  # list of {id, description, ...}
            except Exception as e:
                print(f"  ⚠ Could not connect to {domain} environment at {host}:{port}: {e}")
                print(f"    → Make sure Docker containers are running: "
                      f"docker compose -f docker/docker-compose.agentbench.yml up -d")
                continue

            for item in task_list[:limit]:
                yield AgentBenchTask(
                    task_id     = f"{domain}_{item['id']}",
                    domain      = domain,
                    description = item.get("description", item.get("instruction", str(item))),
                    host        = host,
                    port        = port,
                )

    def check_health(self) -> dict[str, bool]:
        """Check which environments are reachable."""
        health = {}
        for domain, cfg in self.DOMAIN_CONFIG.items():
            host = os.getenv(cfg["env_var_host"], cfg["default_host"])
            port = int(os.getenv(cfg["env_var_port"], cfg["default_port"]))
            try:
                r = requests.get(f"http://{host}:{port}/health", timeout=5)
                health[domain] = r.status_code == 200
            except Exception:
                health[domain] = False
        return health

    # ── Task lifecycle ─────────────────────────────────────────────────────────

    def start_task(self, task: AgentBenchTask) -> str:
        """Start a task and return the initial observation."""
        resp = requests.post(
            f"{task.base_url}/tasks/{task.task_id}/start",
            json={},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        self._sessions[task.task_id] = data.get("session_token", "")
        return data.get("observation", data.get("initial_obs", str(data)))

    def step(self, task: AgentBenchTask, action: str) -> StepResult:
        """Submit an action and return the environment's response."""
        resp = requests.post(
            f"{task.base_url}/tasks/{task.task_id}/step",
            json={
                "action":        action,
                "session_token": self._sessions.get(task.task_id, ""),
            },
            timeout=self._timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        return StepResult(
            observation = data.get("observation", ""),
            reward      = float(data.get("reward", 0.0)),
            done        = bool(data.get("done", False)),
            info        = data.get("info", {}),
        )

    def reset(self, task: AgentBenchTask) -> None:
        """Reset the task environment to its initial state for the next run."""
        try:
            requests.post(
                f"{task.base_url}/tasks/{task.task_id}/reset",
                json={"session_token": self._sessions.get(task.task_id, "")},
                timeout=self._timeout,
            )
        except Exception:
            pass  # Reset failures are non-fatal; task server handles cleanup
        self._sessions.pop(task.task_id, None)
