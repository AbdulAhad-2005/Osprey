# Live Host Probing

**When:** You have a list of hostnames or need to verify HTTP(S) reachability.

**Default:** `httpx_probe` with targets in `target` or `url` param (newline-separated or single).

**Useful `additional_args` examples (not exhaustive):**
- `-title -tech-detect -status-code -follow-redirects`
- `-threads 50` for large lists

**Input:** Pipe subdomains from prior findings or pass a file path if the tool supports it via flags.

**Output:** Live URLs, status codes, technologies — feed into crawling or historical URL tasks.
