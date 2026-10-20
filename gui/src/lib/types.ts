/** Shared types mirroring the Osprey backend contract. */

export interface Engagement {
  id: string;
  target: string;
  name: string;
  status: string;
  findings_count: number;
  tools_executed: number;
  created_at?: string;
  updated_at?: string;
  rules_of_engagement?: RulesOfEngagement;
}

export interface RulesOfEngagement {
  allow_exploitation?: boolean;
  destructive_actions_allowed?: boolean;
  [k: string]: unknown;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "none";

export interface FindingSummary {
  id: string;
  title: string;
  finding_type: string;
  claim_severity: Severity;
  confidence: string;
  target: string;
  source_tool: string;
  phase: string;
  description?: string;
  evidence?: string;
  evidence_summary?: string;
  occurrence_count?: number;
  last_seen_at?: string;
  tags?: string[];
}

/** Typed fact with provenance — the raw material of the attack-surface views. */
export interface Observation {
  id: string;
  type: string;
  details: Record<string, unknown>;
  confidence: string;
  source_tool: string;
  target: string;
  tags: string[];
  signature?: string;
  occurrence_count?: number | null;
  last_seen_at?: string | null;
  created_at?: string;
}

/* --- Canonical report (one backend source) ------------------------------- */

export interface ReportFinding {
  id: string;
  type: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: string;
  source_tool: string;
  target: string;
  evidence_snippet: string;
  remediation_hint: string;
}

export interface ReportData {
  error?: string;
  meta: {
    engagement_id: string;
    target: string;
    name: string;
    status: string;
    generated_at: string;
    started_at: string | null;
    updated_at: string | null;
    tools_executed: number;
  };
  executive_summary: {
    overall_risk: Severity;
    overall_risk_label: string;
    narrative: string;
    key_stats: Record<string, number>;
    top_risks: { title: string; severity: string; target: string }[];
  };
  scope: {
    target: string;
    description: string;
    in_scope: string[];
    out_of_scope: string[];
    allowed_techniques: string[];
    blocked_techniques: string[];
    requires_human_approval: boolean;
    allow_exploitation: boolean;
    allow_post_exploitation: boolean;
    destructive_actions_allowed: boolean;
    rate_limit_rps: number;
    max_concurrent_tools: number;
    time_window: string | null;
  };
  methodology: { phase: string; tools: string[] }[];
  findings_by_severity: { severity: Severity; count: number; findings: ReportFinding[] }[];
  scanner_claims: {
    observation_id: string;
    source_tool: string;
    target: string;
    title: string;
    scanner_claimed_severity: string;
    template_id: string;
    verified: boolean;
  }[];
  infrastructure_notes: { waf_detected: string[]; cloudflare_assets: string[]; email_posture: string[] };
  technologies: string[];
  recon_appendix: {
    key: string;
    label: string;
    count: number;
    items: { type: string; value: string; detail: string; source_tool: string }[];
  }[];
  totals: { findings: number; by_severity: Record<string, number> };
}

/** A node in the engagement attack-surface graph. */
export interface AssetNode {
  id: string;
  asset_type: string;
  label: string;
  confidence: string;
  observation_ids: string[];
  source_tools: string[];
  metadata: Record<string, unknown>;
}

/* --- Chat / agent event stream ------------------------------------------- *
 * The backend's POST /api/v1/agent/chat streams these as SSE. They are a
 * thin, stable projection of cli.agent.loop.Runner's Event objects plus the
 * interactive `question` event the GUI adds. One enum, one renderer. */

export type ChatRole = "user" | "assistant";

export interface QuestionOption {
  value: string;
  label: string;
  /** Optional hint shown under the option. */
  detail?: string;
  /** Visual intent — e.g. an exploitation "go" is `danger`. */
  intent?: "default" | "primary" | "danger";
}

export interface OperatorQuestion {
  id: string;
  text: string;
  options: QuestionOption[];
  /** Freeform answers allowed in addition to options. */
  allow_freeform?: boolean;
  /** Semantic kind so the UI can theme gates distinctly. */
  kind?: "gate" | "scope" | "choice";
}

export type ChatEvent =
  | { event: "message_start"; data: { turn_id: string } }
  | { event: "llm_call_start"; data: Record<string, never> }
  | { event: "llm_still_waiting"; data: { elapsed_seconds: number } }
  | { event: "thinking"; data: { content: string } }
  | { event: "assistant"; data: { content: string } }
  | {
      event: "tool_start";
      data: {
        tool_name: string;
        arguments?: string;
        tool_call_id: string;
        source?: string;
      };
    }
  | {
      event: "tool_end";
      data: {
        tool_name: string;
        result: string;
        success: boolean;
        duration_seconds: number;
        tool_call_id: string;
        finding_titles?: string[];
      };
    }
  | { event: "compaction"; data: { messages_after?: number; forced?: boolean } }
  | { event: "question"; data: OperatorQuestion }
  | { event: "error"; data: { message: string } }
  | { event: "done"; data: { content: string } }
  | { event: "cancelled"; data: { findings?: string } };

export type ChatEventName = ChatEvent["event"];

/* --- Client-side conversation model (what the chat view renders) --------- */

export interface ToolCallView {
  id: string;
  name: string;
  source?: string;
  args?: string;
  status: "running" | "ok" | "fail";
  result?: string;
  durationSeconds?: number;
  findingTitles?: string[];
}

export type TurnBlock =
  | { kind: "text"; id: string; content: string }
  | { kind: "thinking"; id: string; content: string }
  | { kind: "tools"; id: string; calls: ToolCallView[] }
  | { kind: "question"; id: string; question: OperatorQuestion; answered?: string };

export interface ChatTurn {
  id: string;
  role: ChatRole;
  /** For assistant turns: an ordered list of blocks (text, tool batches, …). */
  blocks: TurnBlock[];
  /** For user turns: the raw text. */
  text?: string;
  streaming?: boolean;
}
