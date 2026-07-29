# Document Metadata Harvest

**When:** You want internal names, software, usernames or hostnames leaked in a
domain's **public** documents (PDF/Office files).

**Default:** `metagoofil` (domain=) — enumerate public documents indexed for the
domain, then extract metadata from any downloaded file with `exiftool_extract`
(forensics category — reused, not duplicated).

**Flow:**
1. `metagoofil` domain= file_types="pdf,doc,docx,xls,xlsx,ppt,pptx" limit=50 → document URLs.
2. `exiftool_extract` file_path=<downloaded file> → `Author`, `Creator`, `Producer`,
   `Last Modified By`, software versions, and occasionally GPS.
3. Author / "Last Modified By" values are **PERSON** and **USERNAME** leads → pivot
   with `email_permute`, `holehe`, `maigret`.

**Params:** `metagoofil` domain=; `exiftool_extract` file_path=.

**Grade:** document existence → inferred; extracted author names → treat as person
leads (inferred), usernames as inferred.

**Do not:** treat internal paths/usernames in metadata as live credentials — they are
context leads for the passive identity graph.
