import sys, json
sys.path.insert(0, '.')
results = json.load(open('results/aggregated/injection_standalone_results.json'))
print('DETECTED:')
for id, r in results['per_payload'].items():
    if r['injected']:
        print('  ' + id + ' [' + r['category'] + '] patterns: ' + str(r['patterns']))
print('MISSED (first 5):')
count = 0
for id, r in results['per_payload'].items():
    if not r['injected'] and count < 5:
        print('  ' + id + ' [' + r['category'] + '] conf: ' + str(r['confidence']))
        count += 1
