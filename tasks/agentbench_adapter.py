import requests, time, json
from dataclasses import dataclass

@dataclass
class AgentBenchTask:
    id: str
    description: str
    domain: str

class AgentBenchAdapter:
    def __init__(self, host='localhost', port=5001, domain='os'):
        self.base = f'http://{host}:{port}/api'
        self.domain = domain
        self.session_id = None
        self._counter = int(time.time()) % 10000

    def get_tasks(self, max_tasks=10):
        r = requests.get(f'{self.base}/get_indices', timeout=10)
        indices = r.json()
        return [AgentBenchTask(id=str(i), description=f'Task {i}', domain=self.domain) for i in list(indices)[:max_tasks]]

    def start_task(self, task_id):
        self._counter += 1
        self.session_id = self._counter
        r = requests.post(f'{self.base}/start_sample', json={'index': int(task_id), 'session_id': self.session_id}, timeout=30)
        data = r.json()
        # Server may return its own session_id
        if isinstance(data, dict) and 'session_id' in data:
            self.session_id = data['session_id']
        return data

    def step(self, action):
        r = requests.post(f'{self.base}/interact', json={'session_id': self.session_id, 'messages': [{'role': 'assistant', 'content': action}]}, timeout=60)
        return r.json()

    def get_status(self):
        r = requests.post(f'{self.base}/sample_status', json={'session_id': self.session_id}, timeout=10)
        return r.json()

    def cancel(self):
        try:
            requests.post(f'{self.base}/cancel', json={'session_id': self.session_id}, timeout=10)
        except:
            pass
