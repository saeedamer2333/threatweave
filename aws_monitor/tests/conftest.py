"""Pytest configuration for the aws_monitor test suite."""
from __future__ import annotations

import sys
from pathlib import Path

MONITOR_DIR = Path(__file__).resolve().parent.parent
if str(MONITOR_DIR) not in sys.path:
    sys.path.insert(0, str(MONITOR_DIR))
