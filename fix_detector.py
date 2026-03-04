import pathlib
txt = pathlib.Path('governance/injection_detector.py').read_text()
old = 'r"ignore\\s+(all\\s+)?(previous|prior|above|earlier)\\s+instructions",'
new = 'r"ignore\\s+(all\\s+)?(previous|prior|above|earlier)\\s+instructions",\n        r"(disregard|forget|override|bypass|skip|cancel)\\s+(your\\s+)?(previous|prior|above|all|system|original)",\n        r"(new|updated|revised|changed)\\s+(task|goal|objective|instructions?)\\s*:",'
txt = txt.replace(old, new)
pathlib.Path('governance/injection_detector.py').write_text(txt)
print('Patterns added')
