from __future__ import annotations
import os, uuid
from typing import Any, Callable
from dotenv import load_dotenv
load_dotenv()

try:
    import autogen as ag
    AssistantAgent = ag.AssistantAgent
    UserProxyAgent = ag.UserProxyAgent
    register_function = getattr(ag, 'register_function', None)
except Exception:
    from autogen_agentchat.agents import AssistantAgent, UserProxyAgent
    register_function = None

def build_baseline_agent(task_id, tools, results_dir='./results/raw'):
    session_id = f'baseline_{task_id}_{uuid.uuid4().hex[:8]}'
    session_meta = {'session_id': session_id, 'condition': 'baseline', 'task_id': task_id, 'tool_call_count': 0, 'planner_turn_count': 0, 'tokens_used': 0}
    llm_config = {'config_list': [{'model': os.getenv('OPENAI_MODEL', 'gpt-4o-mini'), 'api_key': os.getenv('OPENAI_API_KEY')}], 'temperature': float(os.getenv('TEMPERATURE', '0.7'))}
    assistant = AssistantAgent(name='baseline_assistant', llm_config=llm_config, system_message='You are a helpful AI assistant. Complete tasks step by step using available tools.')
    user_proxy = UserProxyAgent(name='baseline_executor', human_input_mode='NEVER', max_consecutive_auto_reply=int(os.getenv('MAX_AGENT_TURNS', '15')), code_execution_config=False)
    def make_tracked(name, fn):
        def tracked(**kwargs):
            session_meta['tool_call_count'] += 1
            try: return fn(**kwargs)
            except Exception as e: return f'[TOOL ERROR] {e}'
        tracked.__name__ = name
        return tracked
    if register_function:
        for name, fn in tools.items():
            register_function(make_tracked(name, fn), caller=assistant, executor=user_proxy, name=name, description=f'Tool: {name}')
    return assistant, user_proxy, session_meta
