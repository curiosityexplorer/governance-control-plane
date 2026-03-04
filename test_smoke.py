import sys, os, time, json, pathlib
sys.path.insert(0, '.')
from tasks.agentbench_adapter import AgentBenchAdapter

print('Testing AgentBench connection...')
adapter = AgentBenchAdapter(host='localhost', port=5001, domain='os')
tasks = adapter.get_tasks(max_tasks=5)
print('Got ' + str(len(tasks)) + ' tasks')

results = []
for task in tasks:
    print('Starting task ' + str(task.id))
    try:
        start = adapter.start_task(task.id)
        print('  Started: ' + str(start)[:100])
        step_result = adapter.step('ls -la')
        print('  Step: ' + str(step_result)[:100])
        status = adapter.get_status()
        print('  Status: ' + str(status)[:100])
        adapter.cancel()
        results.append({'task_id': task.id, 'status': 'ok'})
    except Exception as e:
        print('  Error: ' + str(e))
        results.append({'task_id': task.id, 'status': 'error'})

ok = sum(1 for r in results if r['status'] == 'ok')
print('Completed: ' + str(ok) + '/' + str(len(results)) + ' tasks reachable')
