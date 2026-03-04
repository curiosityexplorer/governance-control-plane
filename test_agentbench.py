import requests, time, json

BASE = 'http://localhost:5001/api'

# 1. Get available task indices
r = requests.get(f'{BASE}/get_indices')
print('Indices:', json.dumps(r.json(), indent=2)[:500])
