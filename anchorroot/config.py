"""
Global constants, versioning, and defaults for Anchorroot.

Single source of truth for anything that would otherwise be duplicated
(and drift) across `cli.py`, `pyproject.toml`, and individual modules --
the package version, the CLI's display name/aliases, default output
paths, the bundled resource paths, and the severity-to-risk-score weights
used by `core.models.AuditReport.risk_score()`.
"""

from __future__ import annotations

from pathlib import Path

VERSION = "1.0.0"

APP_NAME = "anchorroot"
#: Console-script name(s) installed by pyproject.toml's [project.scripts].
#: No short alias is defined for this name (the previous brand's `cc` was
#: initials-based and doesn't carry over) -- add one here and in
#: pyproject.toml's [project.scripts] if you want one.
CLI_ALIASES = ("anchorroot",)

#: Prefix every log line carries, e.g. "[anchorroot] INFO: running: tpm ...".
LOG_PREFIX = f"[{APP_NAME}]"

# -- default filesystem locations ------------------------------------------

DEFAULT_REPORT_PATH = Path("reports") / f"{APP_NAME}_report.json"
DEFAULT_BASELINE_PATH = Path("baselines") / "baseline.json"

#: Bundled sample data shipped with the package (see pyproject.toml's
#: package-data declaration) -- not a user config file, just a starting point.
RESOURCES_DIR = Path(__file__).resolve().parent / "resources"
DEFAULT_WHITELIST_PATH = RESOURCES_DIR / "default_whitelist.yaml"

# -- scoring -----------------------------------------------------------

#: Weight applied per finding severity when computing AuditReport.risk_score().
#: Keyed by Severity.name rather than the enum itself to keep this module
#: free of a dependency on core.models (avoids a needless import cycle risk
#: since models.py is a low-level, widely-imported module).
SEVERITY_WEIGHTS = {"INFO": 1, "WARNING": 5, "CRITICAL": 20}
