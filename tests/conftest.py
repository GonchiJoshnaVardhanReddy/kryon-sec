"""Ensure the repo root is on sys.path for test runs (works even when the
package is not installed editable)."""

import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
if str(root) not in sys.path:
    sys.path.insert(0, str(root))
