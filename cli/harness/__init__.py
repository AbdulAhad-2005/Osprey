"""The CLI-owned Osprey harness.

All first-party CLI entry points obtain a :class:`HarnessRuntime` and drive
work through it.  The backend remains an execution and memory service; it is
not the owner of the operator session.
"""

from cli.harness.runtime import HarnessRuntime, get_runtime

__all__ = ["HarnessRuntime", "get_runtime"]
