"""Pytest configuration for the aiops_engine test suite.

The engine modules use flat imports (`from schema import Finding`) rather
than package-relative ones, because they are also run as standalone scripts
via `python engine.py`. Tests need the same sys.path setup so `import schema`,
`import scorer`, etc. resolve the same way they do at runtime.
"""
from __future__ import annotations

import sys
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parent.parent
if str(ENGINE_DIR) not in sys.path:
    sys.path.insert(0, str(ENGINE_DIR))
