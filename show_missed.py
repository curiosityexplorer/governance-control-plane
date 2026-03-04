import sys, json
sys.path.insert(0, '.')
results = json.load(open('results/aggregated/injection_standalone_results.json'))
from tasks.injection_payloads import INJECTION_PAYLOADS
payloads = {p['id']: p for p in INJECTION_PAYLOADS}
print('MISSED PAYLOADS:')
for id, r in results['per_payload'].items():
    if not r['injected']:
        print(id + ' [' + r['category'] + '] ' + payloads[id]['payload'][:80])
