#!/usr/bin/env python3
"""XMonitor entry point."""

import uvicorn

from app.config import load_config

if __name__ == "__main__":
    cfg = load_config()
    uvicorn.run(
        "app.main:app",
        host=cfg["server"]["host"],
        port=cfg["server"]["port"],
        log_level="warning",
        access_log=False,
    )
