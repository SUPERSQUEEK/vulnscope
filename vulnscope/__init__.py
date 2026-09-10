"""vulnscope - a governed, non-intrusive vulnerability assessment layer."""

__version__ = "1.0.0"

from .engine import run_scan
from .scope import Scope, guard, ScopeError
from .findings import Finding, Report

__all__ = ["run_scan", "Scope", "guard", "ScopeError", "Finding", "Report", "__version__"]
