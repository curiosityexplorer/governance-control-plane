# Governance Control Plane — Experimental Harness

Companion repository for:

> **"A Governance Control Plane for Enterprise Agentic AI Systems"**  
> Vivek Acharya — submitted to MDPI Applied Sciences

---

## Experimental Results (as reported in paper)

| Metric | Baseline | Governed |
|--------|----------|----------|
| Policy Violation Rate | 100.0% | **0.0%** |
| Unsafe Tool Attempts Blocked | 0% | **100%** |
| Governance Decision Latency | 0.0 ms | **0.1 ms** |
| Injection Detection Rate (CP-03) | — | **60.0%** (30/50 payloads) |
| Synthetic Policy Tests Passed | — | **26/35 (74.3%)** |

---

## Data Availability

All raw experimental data is in **`results/aggregated/`**:

| File | Description |
|------|-------------|
| `summary_metrics.json` | Table 4 — main results (violation rate, latency, episodes) |
| `full_experiment_results.json` | 150 episode records (baseline + governed, 15 tasks × 5 runs) |
| `synthetic_test_results.json` | 35 synthetic policy test outcomes (CP-01 to CP-10) |
| `injection_standalone_results.json` | 50 injection payload detection results (CP-03) |
| `../paper_tables/table4_main_results.md` | Table 4 formatted for the paper |

---

## Repository Structure

```
governance-control-plane/
├── governance/                  # Control plane implementations
│   ├── policy_engine.py         # CP-01, CP-02 — policy-as-code engine
│   ├── injection_detector.py    # CP-03 — prompt injection scanner
│   ├── trace_logger.py          # CP-06 — structured trace logging
│   └── tool_gating.py           # CP-02 — tool allow-list enforcement
├── agents/
│   ├── baseline_agent.py        # Ungovened AutoGen agent
│   └── governed_agent.py        # Governed AutoGen agent (all controls active)
├── tasks/
│   ├── synthetic_tests.py       # 35 policy probe test cases
│   ├── injection_payloads.py    # 50 adversarial injection payloads
│   └── agentbench_adapter.py    # AgentBench HTTP API adapter
├── results/
│   ├── aggregated/              # ← ALL PAPER DATA IS HERE
│   └── paper_tables/            # Formatted tables for publication
├── docker/
│   └── docker-compose.agentbench.yml
├── run_custom_experiment.py     # Main experiment (150 episodes)
├── run_injection_standalone.py  # CP-03 injection detection test
├── run_experiments.py           # Full harness orchestrator
└── requirements.txt
```

---

## Reproduce Results

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Set your OpenAI API key
echo "OPENAI_API_KEY=your_key_here" > .env

# 3. Run main experiment (baseline vs governed, 150 episodes, ~30 seconds)
python run_custom_experiment.py

# 4. Run injection detection test (50 payloads against CP-03)
python run_injection_standalone.py

# 5. Run full synthetic policy test suite (35 tests)
python run_experiments.py --mode synthetic
```

Results are written to `results/aggregated/`.

---

## Control Catalog

| ID | Control | Layer |
|----|---------|-------|
| CP-01 | Policy-as-Code Enforcement | Policy |
| CP-02 | Tool Allow-List Gating (Least Privilege) | Policy |
| CP-03 | Prompt Injection Detection | Runtime |
| CP-04 | Human-in-the-Loop Escalation | Runtime |
| CP-05 | Sandboxed Execution | Runtime |
| CP-06 | Structured Trace Logging | Observability |
| CP-07 | Post-Action Validation | Runtime |
| CP-08 | Regression Test Harness | Evaluation |
| CP-09 | Drift Detection | Evaluation |
| CP-10 | Signed Audit Package | Observability |


