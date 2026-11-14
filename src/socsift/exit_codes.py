"""Process exit codes shared by every SOCSift command.

The values are deliberately small and stable so they can be used in shell
pipelines and CI jobs::

    0  clean run, no alerts
    1  run completed and produced at least one alert
    2  operational error (bad input, missing file, invalid configuration)

Commands that cannot complete because of a user mistake must return ``2`` and
must never expose a Python traceback.
"""

from __future__ import annotations

from enum import IntEnum


class ExitCode(IntEnum):
    """Stable exit codes for automation and SOC playbook integration."""

    CLEAN = 0
    ALERTS = 1
    ERROR = 2
