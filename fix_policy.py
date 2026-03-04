import pathlib
txt = pathlib.Path('governance/policy_engine.py').read_text()
old = 'str(v).startswith(("/etc", "/root", "/home", "/usr/bin", "/sys"))'
new = 'any(str(v).startswith(p) for p in ["/etc","/root","/home","/usr","/sys","/boot","/var"])'
txt = txt.replace(old, new)
pathlib.Path('governance/policy_engine.py').write_text(txt)
print('Done' if new in txt else 'Pattern not found - already patched or different')
