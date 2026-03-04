# Governance Control Plane — Experimental Harness
### Companion code for: *"Governance Control Planes for Agentic LLM Systems"* (MDPI AI, 2025)

This harness runs the full baseline-vs-governed experiment described in the paper,
produces all metric tables, and exports results ready for copy-paste into the manuscript.

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | ≥ 3.10 | `python3 --version` |
| Docker Desktop | ≥ 24 | Required for AgentBench envs |
| Docker Compose | ≥ 2.20 | Bundled with Docker Desktop |
| OpenAI API key | — | gpt-4o-mini used by default |
| Git | any | To clone AgentBench |

---

## Quick Start (≈ 15 min setup, 2–4 hr run)

```bash
# 1. Clone this repo
git clone https://github.com/agenticstrategylab/governance-control-plane
cd governance-control-plane

# 2. Clone AgentBench alongside it
git clone https://github.com/THUDM/AgentBench ../AgentBench

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Configure secrets
cp .env.example .env
# Edit .env — add your OPENAI_API_KEY

# 5. Start AgentBench Docker environments
docker compose -f docker/docker-compose.agentbench.yml up -d

# 6. Wait for containers to be healthy (≈ 60 s), then run
python run_experiments.py --mode full

# 7. Results land in results/ as JSON + CSV + paper-ready Markdown tables
```

---

## Experiment Modes

```bash
# Full experiment: baseline + governed, all tasks, 10 runs each (~2-4 hr, ~$15-30 API cost)
python run_experiments.py --mode full

# Quick smoke test: 5 tasks, 2 runs each (~10 min, ~$1 API cost)
python run_experiments.py --mode smoke

# Ablation only (requires prior full run results)
python run_experiments.py --mode ablation

# Synthetic policy tests only (no AgentBench, ~5 min, ~$2)
python run_experiments.py --mode synthetic

# Injection stress test only (~20 min, ~$3)
python run_experiments.py --mode injection
```

---

## Project Structure

```
governance-harness/
├── run_experiments.py          # Main entry point — orchestrates all runs
├── requirements.txt
├── .env.example
│
├── governance/                 # The 10 governance controls (CP-01 to CP-10)
│   ├── policy_engine.py        # CP-01: Policy-as-code decision engine
│   ├── tool_gating.py          # CP-02: Least-privilege allow-list enforcement
│   ├── injection_detector.py   # CP-03: Prompt injection scanner
│   ├── escalation.py           # CP-04: Human-in-the-loop escalation queue
│   ├── sandbox.py              # CP-05: Sandboxed tool execution wrapper
│   ├── trace_logger.py         # CP-06: Structured immutable trace logger
│   ├── post_action_validator.py# CP-07: Post-action intent validation
│   ├── evaluator.py            # CP-08/09: Regression harness + drift detector
│   └── audit_packager.py       # CP-10: Tamper-evident audit package generator
│
├── agents/
│   ├── baseline_agent.py       # Unguarded AutoGen agent
│   ├── governed_agent.py       # Governed AutoGen agent (all controls active)
│   └── tools.py                # Tool definitions shared by both agents
│
├── tasks/
│   ├── agentbench_adapter.py   # Loads and wraps AgentBench task environments
│   ├── synthetic_policy_tests.py  # 40 synthetic policy probe test cases
│   └── injection_payloads.py   # 50 crafted injection payload scenarios
│
├── analysis/
│   ├── metrics.py              # Metric definitions and computation
│   ├── ablation.py             # Ablation study runner
│   └── report_generator.py     # Generates paper-ready Markdown/CSV tables
│
├── docker/
│   └── docker-compose.agentbench.yml
│
└── results/                    # Output directory (git-ignored)
    ├── raw/                    # Per-run JSON trace artifacts
    ├── aggregated/             # Aggregated metric CSVs
    └── paper_tables/           # Ready-to-paste Markdown tables
```

---

## Governance Controls Implemented

| ID | Name | Layer | Status |
|----|------|-------|--------|
| CP-01 | Prohibited Action Enforcement | Policy | ✅ Implemented |
| CP-02 | Least-Privilege Tool Gating | Runtime | ✅ Implemented |
| CP-03 | Prompt Injection Detection | Runtime | ✅ Implemented |
| CP-04 | Human-in-the-Loop Escalation | Runtime | ✅ Implemented (auto-approve mode for batch runs) |
| CP-05 | Sandboxed Tool Execution | Runtime | ✅ Implemented |
| CP-06 | Structured Trace Logging | Observability | ✅ Implemented |
| CP-07 | Post-Action Validation | Observability | ✅ Implemented |
| CP-08 | Continuous Regression Evaluation | Evaluation | ✅ Implemented |
| CP-09 | Drift Detection | Evaluation | ✅ Implemented |
| CP-10 | Audit Artifact Packaging | Observability | ✅ Implemented |

---

## AgentBench Task Domains Used

| Domain | # Tasks | Why Chosen |
|--------|---------|-----------|
| OS (Bash) | 20 | File I/O, shell commands — consequential side effects |
| DB (SQL) | 15 | Read/write database actions — policy-relevant |
| WebShop | 10 | Multi-step web navigation — injection surface |

Total: 45 tasks × 2 conditions × 10 runs = **900 agent episodes**

---

## Cost Estimate

| Mode | Tasks | Runs | Est. tokens | Est. cost (gpt-4o-mini) |
|------|-------|------|-------------|------------------------|
| smoke | 5 | 2 | ~50K | ~$0.05 |
| synthetic | 40 probes | 1 | ~80K | ~$0.08 |
| injection | 50 payloads | 1 | ~100K | ~$0.10 |
| full | 45 | 10 | ~18M | ~$18–25 |

---

## Reproducing Paper Results

After a full run, results appear in `results/paper_tables/`. The key files are:

- `table4_main_results.md` — paste into paper Section 5.1
- `table5_ablation.md` — paste into paper Section 5.3
- `injection_results.md` — paste into paper Section 5.2
- `all_metrics_raw.csv` — full raw data for supplementary materials

---

## Citation

```bibtex
@article{acharya2025governance,
  title={Governance Control Planes for Agentic LLM Systems: A Reference Architecture
         and Evaluation Harness Aligned with NIST AI RMF and GenAI Risks},
  author={Acharya, Vivek},
  journal={AI},
  publisher={MDPI},
  year={2025}
}
```
