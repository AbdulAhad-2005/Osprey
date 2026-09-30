"""Osprey CLI's own local agent runtime.

This package contains the ReAct algorithm used by Osprey's CLI harness.  The
CLI supplies the brain (its configured model/key); the backend supplies
capabilities and durable memory.  Lifecycle and session ownership live in
``cli.harness``.  External MCP and the first-party CLI are adapters over the
same platform capability gateway.
"""
