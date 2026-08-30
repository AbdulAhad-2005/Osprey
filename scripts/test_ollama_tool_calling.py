"""Standalone tool-calling probe — isolates whether a local/Ollama model can
emit a proper tool call, independent of the whole platform (no backend, no
Kali container, no engagement). Run this directly on the machine hosting
Ollama.

Usage:
    python scripts/test_ollama_tool_calling.py
    python scripts/test_ollama_tool_calling.py ollama/some-other-model

Reads LLM_MODEL / LLM_API_BASE / LLM_API_KEY from .env by default (same
values the backend uses), or pass a model name as the first argument.
"""
from __future__ import annotations

import os
import sys

from dotenv import load_dotenv

load_dotenv()

import litellm  # noqa: E402

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_subfinder",
            "description": "Enumerate subdomains for a domain using subfinder.",
            "parameters": {
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "The apex domain to scan, e.g. example.com"},
                },
                "required": ["domain"],
            },
        },
    }
]


def main() -> int:
    model = sys.argv[1] if len(sys.argv) > 1 else os.getenv("LLM_MODEL", "")
    api_base = os.getenv("LLM_API_BASE", "") or None
    api_key = os.getenv("LLM_API_KEY", "") or None

    if not model:
        print("No model configured — set LLM_MODEL in .env or pass one as an argument.")
        return 1

    print(f"model:    {model}")
    print(f"api_base: {api_base or '(default)'}")
    print(f"api_key:  {'set' if api_key else '(none)'}")
    print()

    # 1. litellm's own static capability table for this model — this only
    #    reflects an upstream registry entry, not the ACTUAL runtime behavior
    #    of your local weights/quant, but it's a fast first signal.
    try:
        supports = litellm.supports_function_calling(model=model)
        print(f"litellm.supports_function_calling({model!r}) -> {supports}")
    except Exception as exc:
        print(f"litellm.supports_function_calling check failed (non-fatal): {exc}")
    print()

    # 2. The real test: ask the model a question that can ONLY be answered by
    #    calling the tool, and check whether it actually emits a tool_call
    #    instead of just describing what it would do in plain text.
    messages = [
        {
            "role": "system",
            "content": "You are a pentest agent. You MUST use the provided tool to answer — never answer from your own knowledge.",
        },
        {
            "role": "user",
            "content": "Enumerate subdomains for example.com. Use the tool.",
        },
    ]

    kwargs = {"model": model, "messages": messages, "tools": TOOLS, "tool_choice": "auto", "temperature": 0}
    if api_base:
        kwargs["api_base"] = api_base
    if api_key:
        kwargs["api_key"] = api_key

    print("Sending a tool-forcing prompt...")
    try:
        response = litellm.completion(**kwargs)
    except Exception as exc:
        print(f"\nRESULT: FAIL — the request itself errored: {exc}")
        print("This usually means the model/server doesn't accept the `tools` param at all")
        print("(older Ollama server, or a model built without tool-calling template support).")
        return 1

    msg = response.choices[0].message
    tool_calls = getattr(msg, "tool_calls", None) or []

    print()
    print(f"finish_reason: {response.choices[0].finish_reason}")
    print(f"tool_calls:    {len(tool_calls)}")
    if getattr(msg, "content", None):
        preview = msg.content[:300].replace("\n", " ")
        print(f"content:       {preview}{'...' if len(msg.content) > 300 else ''}")

    print()
    if tool_calls:
        for tc in tool_calls:
            print(f"  -> {tc.function.name}({tc.function.arguments})")
        print("\nRESULT: PASS — the model emitted a real tool call.")
        print("If /scan --mcp still shows 0 tool calls in the platform, the problem is")
        print("elsewhere (prompt/schema mismatch, MAX_TOKENS truncation, or the backend's")
        print("own tool-loop) — not the model's basic tool-calling capability.")
        return 0

    print("RESULT: FAIL — request succeeded but the model answered in plain text")
    print("instead of calling the tool. This IS the cause of '0 tool calls' in the")
    print("platform: many small/quantized local models can't reliably follow the")
    print("tool-calling protocol regardless of prompting. Use the no-LLM engine")
    print("instead (`/scan <target> --engine`), or try a model with confirmed tool")
    print("support (e.g. qwen2.5, llama3.1, mistral-nemo — check `ollama show <model>`")
    print("for a 'Tools' capability, or try a larger/less-aggressively-quantized build).")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
