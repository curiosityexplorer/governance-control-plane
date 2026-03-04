# Governance Control Plane — Experimental Harness

Companion repository for: **"A Governance Control Plane for Enterprise Agentic AI Systems"**

## Results (as reported in paper)
| Metric | Value |
|--------|-------|
| Policy Violation Rate (Governed) | 0.0% |
| Policy Violation Rate (Baseline) | 100.0% |
| Injection Detection Rate (CP-03) | 60.0% (30/50 payloads) |
| Synthetic Policy Tests Passed | 26/35 (74.3%) |
| Governance Decision Latency | <0.1ms per tool call |

## Repository Structure
- governance/ — 10 control implementations (CP-01 to CP-10)
- gents/ — Baseline and governed AutoGen agents
- 	asks/ — 35 synthetic tests, 50 injection payloads, AgentBench adapter
- esults/aggregated/ — All raw experimental data (JSON)
- esults/paper_tables/ — Table 4 in markdown
- un_custom_experiment.py — Main experiment runner (150 episodes)
- un_injection_standalone.py — CP-03 injection detection test

## Reproduce Results
pip install -r requirements.txt
python run_custom_experiment.py
python run_injection_standalone.py
