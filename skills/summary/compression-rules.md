---
name: compression-rules
description: "Compression rules for the summary agent: summarize large stdout while preserving exact IPs, hosts, ports, URLs, and exit codes."
phase: summary
tags: [summary, compression]
---

# Compression Rules

- If stdout > 4000 chars, summarize; attach full text only in storage not in LLM context
- For nmap: list open ports as `port/proto service version`
- For subfinder/amass: count + unique hostnames (dedupe)
- For httpx: URL, status code, title, tech if present
- Never suggest next tools — that is phase agent / YAML assist job
