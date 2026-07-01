"""Ensemble AI package.

Submodules are intentionally not imported here. The agent/tool modules touch
runtime services such as SQLite, so keeping package import side-effect free
makes CLI utilities and tests easier to run.
"""

__all__ = []
