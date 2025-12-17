from fastapi import Request
from datetime import datetime
from typing import Any


def write_audit_log(event: str, request: Request, **metadata: Any) -> None:
    """
    Simple audit logger.
    Accepts arbitrary metadata so it never breaks auth flow.
    In production this would forward to SIEM / file / DB.
    """

    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event": event,
        "ip": request.client.host if request.client else None,
        "path": request.url.path,
        "method": request.method,
        "metadata": metadata,
    }


    print(f"[AUDIT] {log_entry}")
