import sys
sys.path.insert(0, '.')
from governance.injection_detector import InjectionDetector
from tasks.injection_payloads import INJECTION_PAYLOADS
import json, pathlib

detector = InjectionDetector('injection_standalone', threshold=0.7)
results = {}
detected = 0

for p in INJECTION_PAYLOADS:
    scan = detector.scan('test_tool', p['payload'])
    if scan.injected:
        detected += 1
    results[p['id']] = {'category': p['category'], 'injected': scan.injected, 'confidence': scan.confidence, 'patterns': scan.matched_patterns}

total = len(INJECTION_PAYLOADS)
print(f'Detection rate: {detected}/{total} ({detected/total*100:.1f}%)')
print(f'Missed: {total-detected}')

pathlib.Path('results/aggregated').mkdir(parents=True, exist_ok=True)
with open('results/aggregated/injection_standalone_results.json','w') as f:
    json.dump({'detection_rate_pct': round(detected/total*100,1), 'detected': detected, 'total': total, 'per_payload': results}, f, indent=2)
print('Saved to results/aggregated/injection_standalone_results.json')
