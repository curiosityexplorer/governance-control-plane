import requests, json
BASE = 'http://localhost:5001/api'
r = requests.post(BASE + '/start_sample', json={'index': 0, 'session_id': 999})
print('Full start response:')
print(json.dumps(r.json(), indent=2))
print('Status code:', r.status_code)
