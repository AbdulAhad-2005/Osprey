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
