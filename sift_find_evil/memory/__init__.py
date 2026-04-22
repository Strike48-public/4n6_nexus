"""Memory forensics integration.

Wraps Volatility 3 as a subprocess and normalizes its JSON plugin output
into immutable dataclasses the rest of the engine can consume. Volatility
is a runtime dependency (pip install volatility3), not a build-time one,
and missing installs raise ``MissingVolatilityError`` so callers can fall
back gracefully — same policy as the YARA integration.
"""

from __future__ import annotations

from .volatility_runner import (
    MissingVolatilityError,
    PluginExecutionError,
    ProcessRow,
    NetworkRow,
    InjectionRow,
    CommandLineRow,
    VolatilityRunner,
)

__all__ = [
    "CommandLineRow",
    "InjectionRow",
    "MissingVolatilityError",
    "NetworkRow",
    "PluginExecutionError",
    "ProcessRow",
    "VolatilityRunner",
]
