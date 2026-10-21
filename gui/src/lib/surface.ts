import type { FindingSummary, Observation, Severity } from "./types";

/** Logical groupings of observation types into attack-surface sections. */
export const SURFACE_BUCKETS = [
  { key: "infra", label: "Domains & Hosts", types: ["subdomain", "host", "ip", "asn", "dns_record", "cert", "waf"] },
  { key: "services", label: "Ports & Services", types: ["port", "service", "banner"] },
  {
    key: "web",
    label: "Web Surface",
    types: ["url", "endpoint", "content_path", "js_endpoint", "technology", "header", "cookie", "redirect", "http_response"],
  },
  {
    key: "identity",
    label: "Identities & OSINT",
    types: ["email", "person", "username", "phone", "social_account", "organization", "document", "account"],
  },
  { key: "secrets", label: "Secrets & Credentials", types: ["credential", "secret"] },
] as const;

export type SurfaceBucketKey = (typeof SURFACE_BUCKETS)[number]["key"];

/** Stat-tile categories shown across the top of the Attack Surface tab. */
export const STAT_CATEGORIES: { key: string; label: string; types: string[] }[] = [
  { key: "subdomain", label: "Subdomains", types: ["subdomain"] },
  { key: "host", label: "Hosts / IPs", types: ["host", "ip"] },
  { key: "port", label: "Open Ports", types: ["port"] },
  { key: "service", label: "Services", types: ["service"] },
  { key: "technology", label: "Technologies", types: ["technology"] },
  { key: "url", label: "URLs / Endpoints", types: ["url", "endpoint", "content_path", "js_endpoint"] },
  { key: "email", label: "Emails", types: ["email"] },
  { key: "person", label: "People", types: ["person", "username"] },
  { key: "phone", label: "Phones", types: ["phone"] },
  { key: "credential", label: "Credentials", types: ["credential"] },
  { key: "secret", label: "Secrets", types: ["secret"] },
];

function str(v: unknown): string {
  return v == null ? "" : String(v);
}

function firstOf(details: Record<string, unknown>, keys: string[]): string {
  for (const k of keys) {
    const v = details[k];
    if (v != null && String(v).trim()) return String(v);
  }
  return "";
}

/** The primary display value for an observation, chosen per type. */
export function obsValue(o: Observation): string {
  const d = o.details ?? {};
  switch (o.type) {
    case "port":
      return `${o.target || firstOf(d, ["host", "ip"])}:${firstOf(d, ["port", "number"])}`.replace(/:$/, "");
    case "service": {
      const host = o.target || firstOf(d, ["host", "ip"]);
      const port = firstOf(d, ["port"]);
      const name = firstOf(d, ["service", "product", "name"]);
      return name ? `${name} @ ${host}${port ? ":" + port : ""}` : `${host}${port ? ":" + port : ""}`;
    }
    case "technology":
      return firstOf(d, ["name", "technology", "product", "value"]) || o.target;
    case "url":
    case "endpoint":
    case "content_path":
    case "js_endpoint":
      return firstOf(d, ["url", "endpoint", "path", "value"]) || o.target;
    case "email":
      return firstOf(d, ["email", "address", "value"]) || o.target;
    case "person":
      return firstOf(d, ["name", "full_name", "value"]) || o.target;
    case "phone":
      return firstOf(d, ["phone", "number", "value"]) || o.target;
    case "credential": {
      const user = firstOf(d, ["username", "email", "user", "login"]);
      const secret = firstOf(d, ["password", "secret", "value", "hash"]);
      // Never mask — the leaked credential IS the finding (AGENTS.md).
      return user && secret ? `${user}:${secret}` : user || secret || o.target;
    }
    case "secret":
      return firstOf(d, ["secret", "token", "key", "value"]) || o.target;
    case "cert":
      return firstOf(d, ["subject", "cn", "common_name", "value"]) || o.target;
    case "asn":
      return firstOf(d, ["asn", "number", "org", "value"]) || o.target;
    case "waf":
      return firstOf(d, ["waf", "vendor", "name", "value"]) || o.target;
    default:
      return o.target || firstOf(d, ["value", "name", "host"]) || o.signature || "—";
  }
}

/** A secondary, type-aware descriptor shown beside the value. */
export function obsDetail(o: Observation): string {
  const d = o.details ?? {};
  switch (o.type) {
    case "port":
      return [firstOf(d, ["service", "protocol"]), firstOf(d, ["state"])].filter(Boolean).join(" · ");
    case "service":
      return [firstOf(d, ["product"]), firstOf(d, ["version"])].filter(Boolean).join(" ");
    case "technology":
      return [firstOf(d, ["version"]), firstOf(d, ["category", "categories"])].filter(Boolean).join(" · ");
    case "subdomain":
    case "host":
      return firstOf(d, ["ip", "status", "status_code", "resolved"]);
    case "url":
    case "endpoint":
      return firstOf(d, ["status", "status_code", "title"]);
    case "credential":
      return firstOf(d, ["source", "origin", "breach", "where"]);
    case "cert":
      return firstOf(d, ["issuer", "expiry", "not_after"]);
    default: {
      // Compact fallback: a couple of informative keys, if any.
      const keys = Object.keys(d).filter((k) => !["value", "name", "host"].includes(k)).slice(0, 2);
      return keys.map((k) => `${k}=${str(d[k]).slice(0, 40)}`).join(" · ");
    }
  }
}

export function countByTypes(observations: Observation[], types: string[]): number {
  const set = new Set(types);
  return observations.reduce((n, o) => (set.has(o.type) ? n + 1 : n), 0);
}

export function bucketObservations(observations: Observation[], types: readonly string[]): Observation[] {
  const set = new Set(types);
  return observations
    .filter((o) => set.has(o.type))
    .sort((a, b) => a.type.localeCompare(b.type) || obsValue(a).localeCompare(obsValue(b)));
}

export function severityRollup(findings: FindingSummary[]): Record<Severity, number> {
  const roll: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0, none: 0 };
  for (const f of findings) {
    const s = (f.claim_severity ?? "none") as Severity;
    roll[s] = (roll[s] ?? 0) + 1;
  }
  return roll;
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info", "none"];
