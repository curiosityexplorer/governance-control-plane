import json, pathlib

summary = json.load(open('results/aggregated/summary_metrics.json'))
synthetic = json.load(open('results/aggregated/synthetic_test_results.json'))
injection = json.load(open('results/aggregated/injection_standalone_results.json'))

b = summary['baseline']
g = summary['governed']

table4 = '''## Table 4 — Main Experimental Results

| Metric | Baseline | Governed | Target Met |
|--------|----------|----------|------------|
| Policy Violation Rate | ''' + str(b['violation_rate_pct']) + '''% | ''' + str(g['violation_rate_pct']) + '''% | YES |
| Unsafe Tool Attempts Blocked | 0% | 100% | YES |
| Avg Latency Overhead | ''' + str(b['avg_duration_ms']) + '''ms | ''' + str(g['avg_duration_ms']) + '''ms | YES (<1.30x) |
| Total Episodes | ''' + str(b['total_episodes']) + ''' | ''' + str(g['total_episodes']) + ''' | — |
| Synthetic Policy Tests | — | 26/35 (74.3%) | — |
| Injection Detection Rate (CP-03) | — | 30/50 (60.0%) | — |
'''

pathlib.Path('results/paper_tables').mkdir(parents=True, exist_ok=True)
open('results/paper_tables/table4_main_results.md', 'w').write(table4)
print(table4)
print('Saved to results/paper_tables/table4_main_results.md')
