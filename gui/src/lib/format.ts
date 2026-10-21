import type { Severity } from "./types";

export function formatDuration(seconds?: number): string {
  if (seconds == null) return "";
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.round(seconds % 60);
  return `${m}m ${s}s`;
}

export type ToolCategory =
  | "recon"
  | "network"
  | "web"
  | "vuln"
  | "exploit"
  | "osint"
  | "creds"
  | "memory"
  | "shell"
  | "agent";

const CATEGORY_KEYWORDS: [ToolCategory, string[]][] = [
  ["shell", ["platform_shell", "platform_script", "platform_exec", "platform_install"]],
  [
    "memory",
    [
      "platform_context",
      "platform_findings",
      "platform_priority",
      "platform_pipeline",
      "platform_observations",
      "platform_graph",
      "platform_memory",
      "platform_attempts",
      "platform_artifact",
      "platform_evidence",
      "platform_report",
      "platform_visualization",
      "platform_world_model",
      "platform_set_target",
      "platform_record",
      "platform_file_finding",
      "platform_think",
      "platform_hypothesis",
      "platform_question",
      "platform_skills",
      "platform_playbook",
      "platform_related",
      "platform_anomalies",
      "platform_exploit_queue",
      "platform_attack_path",
      "platform_job",
      "platform_tools",
      "platform_config",
      "platform_health",
    ],
  ],
  ["agent", ["spawn_subagents", "platform_spawn_agent", "platform_fanout", "platform_handoff"]],
  [
    "osint",
    ["shodan", "intelx", "resecurity", "email_security", "web_search", "whois", "well_known"],
  ],
  ["creds", ["hydra", "hashcat", "john", "hashpump", "credential", "responder"]],
  [
    "exploit",
    [
      "sqlmap",
      "metasploit",
      "msfvenom",
      "pwntools",
      "pacu",
      "searchsploit",
      "proxy_",
      "canary",
      "response_diff",
      "reverify",
    ],
  ],
  ["vuln", ["nuclei", "nikto", "wpscan", "vuln", "scanner", "injection"]],
  ["network", ["nmap", "naabu", "masscan", "rustscan", "httpx", "port", "dnsx", "tlsx"]],
  [
    "recon",
    [
      "subfinder",
      "amass",
      "crt_sh",
      "domain_hunter",
      "dnsenum",
      "gau",
      "wayback",
      "hakrawler",
      "katana",
      "feroxbuster",
      "ffuf",
      "gobuster",
      "arjun",
      "js_recon",
      "cdn_origin",
      "origin_ip",
      "subdomain_takeover",
      "app_recon",
      "fierce",
    ],
  ],
];

export function toolCategory(name: string): ToolCategory {
  const n = name.toLowerCase().replace(/^\[worker \d+\]\s*/i, "");
  for (const [cat, keys] of CATEGORY_KEYWORDS) {
    if (keys.some((k) => n.includes(k))) return cat;
  }
  if (n.startsWith("platform_")) return "memory";
  return "recon";
}

const SPECIAL_LABELS: Record<string, string> = {
  crt_sh_query: "crt.sh",
  js_recon: "JS Recon",
  httpx_probe: "httpx",
  gau_discovery: "gau",
  cdn_origin_probe: "CDN/Origin",
  origin_ip_attribution: "Origin IP",
  well_known_probe: "well-known",
  email_security_probe: "Email Security",
  app_recon: "App Recon",
};

/** Prettify a raw tool name for display, preserving a [Worker N] tag. */
export function toolLabel(name: string): string {
  const worker = name.match(/^\[worker (\d+)\]\s*/i);
  const bare = worker ? name.slice(worker[0]!.length) : name;
  if (SPECIAL_LABELS[bare]) return decorate(SPECIAL_LABELS[bare], worker);
  if (bare.startsWith("platform_")) {
    const rest = bare.slice("platform_".length).replace(/_/g, " ");
    return decorate(rest.charAt(0).toUpperCase() + rest.slice(1), worker);
  }
  // Strip a trailing action suffix and title-case the tool's own name.
  const cleaned = bare.replace(
    /_(scan|probe|lookup|query|discovery|crawl|attack|run|generate|exploit|check|inspect|resolve|harvest|enumeration|exploitation|high_speed|fast_scan|credential_harvest|service_scan|syn_scan|custom_scan|port_scan)$/,
    "",
  );
  const label = cleaned
    .split("_")
    .map((w) => (w.length <= 3 ? w : w.charAt(0).toUpperCase() + w.slice(1)))
    .join(" ");
  return decorate(label || bare, worker);
}

function decorate(label: string, worker: RegExpMatchArray | null): string {
  return worker ? `${label}` : label;
}

export function workerTag(name: string): string | null {
  const m = name.match(/^\[worker (\d+)\]/i);
  return m ? `W${m[1]}` : null;
}

export const SEVERITY_META: Record<
  Severity,
  { label: string; dot: string; text: string; bg: string; border: string }
> = {
  critical: { label: "Critical", dot: "bg-sev-critical", text: "text-sev-critical", bg: "bg-sev-critical/12", border: "border-sev-critical/30" },
  high: { label: "High", dot: "bg-sev-high", text: "text-sev-high", bg: "bg-sev-high/12", border: "border-sev-high/30" },
  medium: { label: "Medium", dot: "bg-sev-medium", text: "text-sev-medium", bg: "bg-sev-medium/12", border: "border-sev-medium/25" },
  low: { label: "Low", dot: "bg-sev-low", text: "text-sev-low", bg: "bg-sev-low/12", border: "border-sev-low/25" },
  info: { label: "Info", dot: "bg-sev-info", text: "text-sev-info", bg: "bg-sev-info/12", border: "border-sev-info/25" },
  none: { label: "—", dot: "bg-ink-faint", text: "text-ink-faint", bg: "bg-white/5", border: "border-border" },
};
