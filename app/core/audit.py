import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import Request

LOG_PATH = Path("logs/audit.jsonl")
LOG_PATH.parent.mkdir(exist_ok=True)


def write_audit_log(
    *,
    event: str,
    actor_user_id: Optional[int],
    target_user_id: Optional[int],
    details: dict,
    request: Optional[Request] = None,
) -> None:
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event": event,
        "actor_user_id": actor_user_id,
        "target_user_id": target_user_id,
        "details": details,
    }

    if request and request.client:
        entry["ip"] = request.client.host

    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
