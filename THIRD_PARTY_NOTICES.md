# Third-Party Notices

This project incorporates and is informed by third-party open-source work. We
gratefully acknowledge the following projects. Where code was reused, the
originating license is reproduced below and continues to govern those portions;
the project as a whole is licensed under AGPL-3.0 (see `LICENSE`).

---

## HexStrike AI — reused code (MIT)

Portions of this project's tool command-builder layer (`mcp-servers/**/tools/*.py`
`build_command()` recipes and their tool→CLI mappings) and the execution
recovery/graceful-degradation logic (an adaptation of HexStrike's
`IntelligentErrorHandler` / `GracefulDegradation`, originally in
`hexstrike_server.py`) are derived from HexStrike AI. These portions remain
subject to the MIT License reproduced below.

Note: invocation patterns for public third-party security tools (e.g. the flags
passed to `nmap`, `sqlmap`, `ghidra`) are public technical facts and are not
themselves owned by any project; much of this layer is an independent
reimplementation. The MIT notice below is retained for the portions that are a
substantial reuse of HexStrike source.

```
MIT License

Copyright (c) 2026 Muhammad Osama (0x4m4) <contact@0x4m4.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Strix — design influence (Apache-2.0)

No Strix source code is included in this project. Strix (https://github.com/usestrix/strix,
Apache License 2.0) informed design decisions only — the autonomous-harness model,
multi-agent orchestration, and the `SKILL.md` description-frontmatter skill format.
Ideas and architecture are not covered by copyright; this acknowledgment is made
as a courtesy and for transparency.

---

## Anthropic Cybersecurity Skills — skills (Apache-2.0)

Where skills are adapted from the Anthropic Cybersecurity Skills collection
(https://github.com/anthropics/..., Apache License 2.0), the adapted skill files
retain their original license and attribution headers, and the `SKILL.md`
frontmatter format is followed. Their MITRE ATT&CK / NIST CSF mappings are reused
under Apache-2.0.

---

## Additional design influences (acknowledged, no code reused)

The platform's architecture was synthesized from studying several projects. These
are acknowledged as influences only — no source code from them is included, and
design ideas are not subject to copyright:

- **Dark-Moon** — cross-asset pivot / engagement-graph and WAF-pivot escalation concepts.
- **Shannon** — durable phased engagement and evidence-confidence concepts.

---

*If you believe any attribution here is incomplete or incorrect, please open an
issue so we can correct it.*
