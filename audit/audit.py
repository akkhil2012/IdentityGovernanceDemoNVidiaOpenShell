import json
import time
from typing import Dict, Any


class AuditLogger:
    def __init__(self, path: str = "audit/audit.jsonl"):
        self.path = path
        # Ensure directory exists
        import os
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    def log(self, entry: Dict[str, Any]):
        entry = dict(entry)
        entry["ts"] = int(time.time())
        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")
