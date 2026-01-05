# analyzer/rules.py
import json, os
def load_rules_from_file(path):
    if not path: return []
    if not os.path.exists(path): return []
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
            if isinstance(data, list):
                return data
    except Exception:
        return []
    return []
