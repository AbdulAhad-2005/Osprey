"""Live web dashboard: one self-contained HTML page per engagement that
subscribes to the existing ``/agent/events/{engagement_id}`` SSE stream
(``event_bus``) and renders every tool call as it happens.

No new event plumbing lives here — ``tool_execution.execute_tool_request``
(the single execution kernel every path shares: MCP calls, the CLI's
free-LLM loop, the deterministic ``--engine``/``--supervised`` investigation
drivers, background jobs) already publishes ``tool_start``/``tool_end`` onto
``event_bus`` for every tool call, so this page sees everything automatically
and identically regardless of which harness mode is driving.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/{engagement_id}", response_class=HTMLResponse, summary="Live tool-activity dashboard")
def dashboard_page(engagement_id: str) -> HTMLResponse:
    from osprey.services.engagement_store import get_engagement_store

    eid = (engagement_id or "").strip()
    engagement = get_engagement_store().get(eid) if eid else None
    target = engagement.target if engagement else eid
    html = _PAGE.replace("__ENGAGEMENT_ID__", eid).replace("__TARGET__", target or eid)
    return HTMLResponse(html)


_PAGE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Osprey — __TARGET__</title>
<style>
  :root{
    --bg:#0b0e14; --panel:#11151d; --panel-2:#161b25; --border:#232838;
    --text:#dbe2f0; --text-dim:#7d879c; --accent:#3dd6b0; --accent-dim:#1f6f5c;
    --danger:#ef5b6f; --warn:#e7b854; --mono:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,sans-serif;
  }
  *{box-sizing:border-box}
  html,body{margin:0;height:100%;background:var(--bg);color:var(--text);font-family:var(--sans);}
  body{display:flex;flex-direction:column;min-height:100vh;}

  header{
    position:sticky;top:0;z-index:5;display:flex;align-items:center;gap:16px;
    padding:14px 22px;background:linear-gradient(180deg,var(--panel),rgba(17,21,29,0.92));
    border-bottom:1px solid var(--border);backdrop-filter:blur(6px);
  }
  header .brand{display:flex;align-items:center;gap:10px;font-weight:600;letter-spacing:0.2px;}
  header .brand .dot{width:9px;height:9px;border-radius:50%;background:var(--accent);
    box-shadow:0 0 0 0 rgba(61,214,176,.6);animation:pulse 2s infinite;}
  @keyframes pulse{
    0%{box-shadow:0 0 0 0 rgba(61,214,176,.55)}
    70%{box-shadow:0 0 0 8px rgba(61,214,176,0)}
    100%{box-shadow:0 0 0 0 rgba(61,214,176,0)}
  }
  header .target{color:var(--text-dim);font-size:13px;}
  header .target b{color:var(--text);font-weight:600;}
  header .stats{display:flex;gap:18px;margin-left:auto;font-size:13px;color:var(--text-dim)}
  header .stats span b{color:var(--text);font-variant-numeric:tabular-nums;}
  header .status-pill{
    font-size:11px;padding:3px 9px;border-radius:999px;border:1px solid var(--border);
    color:var(--text-dim);letter-spacing:.3px;text-transform:uppercase;
  }
  header .status-pill.live{color:var(--accent);border-color:var(--accent-dim);background:rgba(61,214,176,.08)}
  header .status-pill.down{color:var(--danger);border-color:#5c2733;background:rgba(239,91,111,.08)}
  header button{
    background:var(--panel-2);color:var(--text);border:1px solid var(--border);border-radius:7px;
    padding:7px 13px;font-size:12.5px;cursor:pointer;font-family:var(--sans);transition:border-color .15s;
  }
  header button:hover{border-color:var(--accent-dim)}

  .toolbar{
    display:flex;align-items:center;gap:10px;padding:10px 22px;border-bottom:1px solid var(--border);
    background:rgba(17,21,29,.5);
  }
  .toolbar input[type=text]{
    flex:1;max-width:360px;background:var(--panel-2);border:1px solid var(--border);border-radius:7px;
    color:var(--text);padding:7px 11px;font-size:13px;font-family:var(--sans);
  }
  .toolbar input[type=text]:focus{outline:none;border-color:var(--accent-dim)}
  .toolbar label{display:flex;align-items:center;gap:6px;font-size:12.5px;color:var(--text-dim);cursor:pointer;user-select:none}

  main{flex:1;padding:18px 22px 60px;max-width:1080px;width:100%;margin:0 auto;}
  #empty{color:var(--text-dim);text-align:center;padding:60px 0;font-size:14px}

  .card{
    background:var(--panel);border:1px solid var(--border);border-radius:10px;margin-bottom:10px;
    overflow:hidden;animation:in .2s ease-out;
  }
  @keyframes in{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:none}}
  .card-head{display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;}
  .card-head:hover{background:rgba(255,255,255,.02)}
  .badge{width:8px;height:8px;border-radius:50%;flex:none}
  .badge.running{background:var(--warn);animation:pulse 1.4s infinite}
  .badge.ok{background:var(--accent)}
  .badge.fail{background:var(--danger)}
  .tool-name{font-family:var(--mono);font-weight:600;font-size:13.5px;color:var(--text)}
  .source-tag{font-size:10.5px;color:var(--accent);background:rgba(61,214,176,.1);
    border:1px solid var(--accent-dim);border-radius:5px;padding:1px 6px;font-family:var(--mono);}
  .target-tag{font-size:12px;color:var(--text-dim);font-family:var(--mono)}
  .meta{margin-left:auto;display:flex;align-items:center;gap:12px;font-size:11.5px;color:var(--text-dim)}
  .findings-count{color:var(--accent)}
  .chev{color:var(--text-dim);font-size:11px;transition:transform .15s}
  .card.open .chev{transform:rotate(90deg)}
  .card-body{display:none;border-top:1px solid var(--border);}
  .card.open .card-body{display:block}
  .card-body pre{
    margin:0;padding:14px;font-family:var(--mono);font-size:12.3px;line-height:1.55;
    color:#c3cbdb;white-space:pre-wrap;word-break:break-word;max-height:520px;overflow:auto;
    background:#0d1017;
  }
  .card-body .findings{padding:10px 14px;border-top:1px solid var(--border);display:flex;flex-wrap:wrap;gap:6px}
  .finding-chip{font-size:11px;color:#f0e6b8;background:rgba(231,184,84,.1);border:1px solid #4d4225;
    border-radius:5px;padding:2px 8px;font-family:var(--mono)}
  .params{padding:8px 14px;font-size:11.5px;color:var(--text-dim);font-family:var(--mono);
    border-top:1px solid var(--border);background:rgba(255,255,255,.015)}

  footer{padding:10px 22px;text-align:center;color:var(--text-dim);font-size:11px}
  ::-webkit-scrollbar{width:9px;height:9px}
  ::-webkit-scrollbar-thumb{background:#252b3a;border-radius:6px}
  ::-webkit-scrollbar-track{background:transparent}
</style>
</head>
<body>
  <header>
    <div class="brand"><span class="dot"></span>Osprey</div>
    <div class="target">engagement <b>__TARGET__</b></div>
    <span id="status" class="status-pill">connecting…</span>
    <div class="stats">
      <span>tools <b id="stat-tools">0</b></span>
      <span>running <b id="stat-running">0</b></span>
      <span>findings <b id="stat-findings">0</b></span>
    </div>
    <button id="download">Download .md</button>
  </header>
  <div class="toolbar">
    <input id="filter" type="text" placeholder="Filter by tool or target…">
    <label><input id="autoscroll" type="checkbox" checked> auto-scroll</label>
    <label><input id="onlyfindings" type="checkbox"> only with findings</label>
  </div>
  <main>
    <div id="empty">Waiting for the first tool call…</div>
    <div id="feed"></div>
  </main>
  <footer>__ENGAGEMENT_ID__ · live stream via /api/v1/agent/events</footer>

<script>
const engagementId = "__ENGAGEMENT_ID__";
const feed = document.getElementById("feed");
const empty = document.getElementById("empty");
const statusEl = document.getElementById("status");
const cards = new Map(); // key -> {el, entry}
let seq = 0;
let toolsSeen = 0, running = 0, findingsTotal = 0;

function esc(s){
  return String(s ?? "").replace(/[&<>]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;"}[c]));
}
function fmtDur(s){
  s = Number(s) || 0;
  return s < 1 ? Math.round(s*1000)+"ms" : s.toFixed(1)+"s";
}
function updateStats(){
  document.getElementById("stat-tools").textContent = toolsSeen;
  document.getElementById("stat-running").textContent = running;
  document.getElementById("stat-findings").textContent = findingsTotal;
}

function render(entry){
  let el = cards.get(entry.key);
  if(!el){
    el = document.createElement("div");
    el.className = "card";
    el.dataset.key = entry.key;
    el.innerHTML = `
      <div class="card-head">
        <span class="badge running"></span>
        <span class="tool-name"></span>
        <span class="source-tag"></span>
        <span class="target-tag"></span>
        <span class="meta"><span class="dur"></span><span class="fc findings-count"></span><span class="chev">▶</span></span>
      </div>
      <div class="card-body">
        <div class="params"></div>
        <pre class="out"></pre>
        <div class="findings"></div>
      </div>`;
    el.querySelector(".card-head").addEventListener("click", () => el.classList.toggle("open"));
    feed.prepend(el);
    cards.set(entry.key, el);
    empty.style.display = "none";
  }
  const badge = el.querySelector(".badge");
  badge.className = "badge " + (entry.status === "running" ? "running" : entry.success ? "ok" : "fail");
  el.querySelector(".tool-name").textContent = entry.tool;
  el.querySelector(".source-tag").textContent = entry.source || "tool";
  el.querySelector(".target-tag").textContent = entry.target || "";
  el.querySelector(".dur").textContent = entry.status === "running" ? "running…" : fmtDur(entry.duration);
  el.querySelector(".fc").textContent = entry.findings.length ? `${entry.findings.length} finding${entry.findings.length>1?"s":""}` : "";
  el.querySelector(".params").textContent = entry.params ? JSON.stringify(entry.params) : "";
  el.querySelector(".out").textContent = entry.output || (entry.status === "running" ? "(running…)" : "(no output)");
  const fdiv = el.querySelector(".findings");
  fdiv.innerHTML = entry.findings.map(f => `<span class="finding-chip">${esc(f)}</span>`).join("");
  applyFilter(el, entry);
}

function applyFilter(el, entry){
  const q = document.getElementById("filter").value.trim().toLowerCase();
  const onlyFindings = document.getElementById("onlyfindings").checked;
  let show = true;
  if(q) show = (entry.tool + " " + entry.target).toLowerCase().includes(q);
  if(show && onlyFindings) show = entry.findings.length > 0;
  el.style.display = show ? "" : "none";
}

document.getElementById("filter").addEventListener("input", () => {
  for(const [key, el] of cards) applyFilter(el, entries.get(key));
});
document.getElementById("onlyfindings").addEventListener("change", () => {
  for(const [key, el] of cards) applyFilter(el, entries.get(key));
});

const entries = new Map(); // key -> entry data (for export + refilter)

function toMarkdown(){
  const ordered = [...entries.values()].sort((a,b) => a.seq - b.seq);
  let lines = [`# Osprey session — ${engagementId}`, "", `Target: __TARGET__`, `Exported: ${new Date().toISOString()}`, ""];
  for(const e of ordered){
    lines.push(`## ${e.tool} — ${e.target || "n/a"}`);
    lines.push(`- source: ${e.source || "tool"}`);
    lines.push(`- status: ${e.status === "running" ? "running (not finished)" : (e.success ? "success" : "failed")}`);
    if(e.status !== "running") lines.push(`- duration: ${fmtDur(e.duration)}`);
    if(e.params) lines.push(`- params: \`${JSON.stringify(e.params)}\``);
    if(e.findings.length) lines.push(`- findings: ${e.findings.map(f => "`"+f+"`").join(", ")}`);
    lines.push("", "```", (e.output || "(no output)").slice(0, 20000), "```", "");
  }
  return lines.join("\n");
}

document.getElementById("download").addEventListener("click", () => {
  const blob = new Blob([toMarkdown()], {type: "text/markdown"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `osprey-${engagementId}.md`;
  a.click();
  URL.revokeObjectURL(a.href);
});

function upsert(key, patch){
  let entry = entries.get(key);
  if(!entry){
    entry = {key, seq: seq++, findings: [], status: "running", success: true, duration: 0, output: "", params: null, source: ""};
    entries.set(key, entry);
  }
  Object.assign(entry, patch);
  render(entry);
}

function connect(){
  const es = new EventSource(`/api/v1/agent/events/${engagementId}`);
  es.onopen = () => { statusEl.textContent = "live"; statusEl.className = "status-pill live"; };
  es.onerror = () => { statusEl.textContent = "reconnecting…"; statusEl.className = "status-pill down"; };
  es.addEventListener("tool_start", (ev) => {
    const d = JSON.parse(ev.data);
    const key = `${d.tool_name}:${d.target}:${seq}`;
    toolsSeen++; running++; updateStats();
    upsert(key, {tool: d.tool_name, target: d.target, params: d.params, source: d.source || "tool", status: "running"});
    upsert.lastKey = key;
    pendingByTool.set(`${d.tool_name}:${d.target}`, key);
  });
  es.addEventListener("tool_end", (ev) => {
    const d = JSON.parse(ev.data);
    const pk = `${d.tool_name}:${d.target}`;
    const key = pendingByTool.get(pk) || pk;
    pendingByTool.delete(pk);
    running = Math.max(0, running - 1);
    findingsTotal += (d.finding_titles || []).length;
    updateStats();
    upsert(key, {
      tool: d.tool_name, target: d.target, source: d.source || "tool",
      status: "done", success: !!d.success, duration: d.duration_seconds || 0,
      output: d.stdout || "", findings: d.finding_titles || [],
    });
  });
  es.onmessage = () => {}; // default channel unused; named events above carry everything
}
const pendingByTool = new Map();
connect();
</script>
</body>
</html>
"""
