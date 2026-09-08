"""Ensure the package source is on sys.path for test runs (works even when
the package is not installed editable). The package lives at src/kryonsec —
inserting the repo root alone would not make `import kryonsec` work."""

import sys
from pathlib import Path

src = Path(__file__).resolve().parents[1] / "src"
if str(src) not in sys.path:
    sys.path.insert(0, str(src))
