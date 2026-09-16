"""
Centralized logging for CounterCraft.

Every line goes through here rather than ad hoc `print(..., file=sys.stderr)`
calls, so status/progress/error output is consistently tagged
`[countercraft]` (grep-able, and distinguishable from a module's own
findings when output is piped or redirected) and its verbosity is
controlled in one place.
"""

from __future__ import annotations

import logging
import sys

from countercraft.config import LOG_PREFIX

_LOG_FORMAT = f"{LOG_PREFIX} %(levelname)s: %(message)s"


def get_logger(name: str = "countercraft") -> logging.Logger:
    """
    Return the named logger, configuring it on first use. Safe to call
    repeatedly (e.g. once per module) -- only attaches a handler once.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(_LOG_FORMAT))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def set_verbosity(quiet: bool = False, verbose: bool = False) -> None:
    """Adjust the root CounterCraft logger's level. Called once from the CLI."""
    logger = get_logger()
    if quiet:
        logger.setLevel(logging.WARNING)
    elif verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)


#: Module-level default logger -- `from countercraft.utils.logger import logger`
#: is the common case; use `get_logger(__name__)` instead if a piece of code
#: wants its own named logger for finer-grained filtering.
logger = get_logger()
