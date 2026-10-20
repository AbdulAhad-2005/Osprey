"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape, { type Core } from "cytoscape";
import dagre from "cytoscape-dagre";
import { Maximize2, RefreshCw, Network, X, Search } from "lucide-react";
import { getGraph } from "@/lib/api";
import { useResource } from "@/hooks/useResource";
import type { Severity } from "@/lib/types";
import { processGraph, type Cluster, type GNodeData } from "@/lib/graphModel";
import { SEVERITY_META } from "@/lib/format";
import { cn } from "@/lib/cn";
import { Loading, EmptyState, ErrorState } from "@/components/ui/States";

let dagreRegistered = false;
function ensureDagre() {
  if (!dagreRegistered) {
    cytoscape.use(dagre);
    dagreRegistered = true;
  }
}

/* Muted, cohesive type backgrounds — the graph stays calm and neutral so that
 * RISK (the severity border, below) is the thing that pops, not a rainbow of
 * node colours. */
const TYPE_BG: Record<string, string> = {
  domain: "#273751",
  subdomain: "#233044",
  host: "#1f3647",
  ip: "#1f3647",
  service: "#1d3a37",
  port: "#1b2f3a",
  technology: "#1e3630",
  email: "#2b2846",
  person: "#2b2846",
  username: "#2b2846",
  phone: "#2b2846",
  organization: "#39273f",
  credential: "#3a2a1c",
  secret: "#3a2a1c",
  url: "#222a39",
  cluster: "#1a2233",
};
// A small leading dot per type so the category is still legible at a glance.
const TYPE_DOT: Record<string, string> = {
  domain: "#f5a623",
  subdomain: "#58b0f0",
  host: "#7fa7c8",
  ip: "#7fa7c8",
  service: "#4fd1c5",
  port: "#38bdf8",
  technology: "#4ade80",
  email: "#b79af6",
  person: "#b79af6",
  username: "#b79af6",
  phone: "#b79af6",
  organization: "#f472b6",
  credential: "#ff9d5c",
  secret: "#ff9d5c",
  url: "#8696b0",
  cluster: "#9aa7bd",
};
const SEV_COLOR: Record<string, string> = {
  critical: "#ff5d6c",
  high: "#ff8a4c",
  medium: "#ffc53d",
  low: "#5eb0ef",
};
// Orient edges parent → child so the hierarchy reads cleanly left-to-right.
const REVERSE_EDGE = new Set(["subdomain_of", "hosted_on"]);

function dot(d: GNodeData): string {
  return TYPE_DOT[d.isCluster ? (d.clusterType ?? "cluster") : d.type] ?? "#8696b0";
}
function bg(d: GNodeData): string {
  if (d.primary) return "#7a5415";
  return TYPE_BG[d.isCluster ? (d.clusterType ?? "cluster") : d.type] ?? "#222a39";
}

function buildStyle(): cytoscape.Stylesheet[] {
  return [
    {
      selector: "node",
      // `padding` (label-box sizing) and `width: "label"` are valid cytoscape
      // node styles but missing from the shipped TS types — hence the cast.
      style: {
        shape: "round-rectangle",
        "background-color": "data(bg)",
        "border-width": "data(ring)",
        "border-color": "data(ringColor)",
        width: "label",
        height: 26,
        padding: "8px",
        label: "data(label)",
        color: "#dbe2ee",
        "font-size": 11,
        "font-family": "ui-monospace, 'JetBrains Mono', SFMono-Regular, Menlo, monospace",
        "text-valign": "center",
        "text-halign": "center",
        "text-wrap": "ellipsis",
        "text-max-width": "190px",
        "min-zoomed-font-size": 7,
      } as unknown as cytoscape.Css.Node,
    },
    { selector: "node[primaryFlag = 1]", style: { color: "#fff6e6", "font-size": 13, "font-weight": 700, height: 34 } },
    { selector: 'node[kind = "domain"]', style: { "font-size": 12, "font-weight": 600, height: 30 } },
    { selector: "node[isClusterFlag = 1]", style: { "font-style": "italic", color: "#aeb8c9", "border-style": "dashed" } },
    { selector: "node.dim", style: { opacity: 0.2 } },
    { selector: "node.hidden", style: { display: "none" } },
    { selector: "node.lit", style: { "border-color": "#f5a623", "border-width": 2.5, "z-index": 30, color: "#fff" } },
    { selector: "node.pinned", style: { "border-color": "#f5a623", "border-width": 3 } },
    {
      selector: "edge",
      style: {
        width: 1.3,
        "line-color": "#30415f",
        "target-arrow-color": "#30415f",
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.8,
        "curve-style": "taxi",
        "taxi-direction": "horizontal",
        "taxi-turn": 24,
        "taxi-turn-min-distance": 8,
        label: "",
      },
    },
    { selector: "edge[hypothesisFlag = 1]", style: { "line-style": "dashed", "line-color": "#c47d10", "target-arrow-color": "#c47d10" } },
    { selector: "edge.lit", style: { "line-color": "#6f86ad", "target-arrow-color": "#6f86ad", width: 2, "z-index": 25 } },
    { selector: "edge.dim", style: { opacity: 0.08 } },
    { selector: "edge.hidden", style: { display: "none" } },
  ];
}

function layoutOpts(): cytoscape.LayoutOptions {
  return {
    name: "dagre",
    rankDir: "LR",
    nodeSep: 16,
    rankSep: 70,
    edgeSep: 8,
    ranker: "network-simplex",
    animate: true,
    animationDuration: 500,
    fit: true,
    padding: 40,
  } as unknown as cytoscape.LayoutOptions;
}

interface Inspect {
  kind: "node" | "cluster";
  id: string;
  label: string;
  type: string;
  severity: Severity;
  neighbors?: { label: string; rel: string; dir: "out" | "in" }[];
  cluster?: Cluster;
}

// Prefix the label with a small swatch glyph so the type colour reads inside the
// box without an extra DOM layer. ◆ tinted via a leading space keeps it subtle.
function labelWith(d: GNodeData): string {
  const base = d.label.length > 40 ? d.label.slice(0, 39) + "…" : d.label;
  return d.isCluster ? `▸ ${base}` : base;
}

export function GraphTab({ engagementId }: { engagementId: string }) {
  const graphRes = useResource((s) => getGraph(engagementId, s), [engagementId]);
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const pinnedRef = useRef<string | null>(null);
  const [inspect, setInspect] = useState<Inspect | null>(null);
  const [query, setQuery] = useState("");

  const processed = useMemo(
    () => (graphRes.data ? processGraph(graphRes.data) : null),
    [graphRes.data],
  );

  useEffect(() => {
    if (!containerRef.current || !processed || processed.nodes.length === 0) return;
    ensureDagre();
    const clusters = processed.clusters;

    const nodes = processed.nodes.map((n) => {
      const sev = n.data.severity && n.data.severity !== "none" ? n.data.severity : null;
      return {
        data: {
          ...n.data,
          bg: bg(n.data),
          dot: dot(n.data),
          label: labelWith(n.data),
          ring: sev ? 2.5 : 1,
          ringColor: sev ? SEV_COLOR[sev] : "rgba(120,140,175,0.35)",
          isClusterFlag: n.data.isCluster ? 1 : 0,
          primaryFlag: n.data.primary ? 1 : 0,
          kind: n.data.type,
        },
      };
    });
    const edges = processed.edges.map((e) => {
      const rev = REVERSE_EDGE.has(e.data.label);
      return {
        data: {
          id: e.data.id,
          source: rev ? e.data.target : e.data.source,
          target: rev ? e.data.source : e.data.target,
          label: e.data.label,
          hypothesisFlag: e.data.hypothesis ? 1 : 0,
        },
      };
    });

    const cy = cytoscape({
      container: containerRef.current,
      elements: { nodes, edges },
      style: buildStyle(),
      layout: layoutOpts(),
      wheelSensitivity: 0.2,
      minZoom: 0.1,
      maxZoom: 2.5,
      pixelRatio: 1,
    });
    cyRef.current = cy;

    const fitAll = () => cy.fit(cy.elements(":visible"), 40);
    cy.one("layoutstop", () => {
      cy.resize();
      fitAll();
    });
    const raf = requestAnimationFrame(() => {
      cy.resize();
      fitAll();
    });

    const lit = (n: cytoscape.NodeSingular) => {
      cy.elements().addClass("dim");
      const hood = n.closedNeighborhood();
      hood.removeClass("dim").addClass("lit");
      n.connectedEdges().removeClass("dim").addClass("lit");
    };
    const clear = () => cy.elements().removeClass("lit dim");

    cy.on("mouseover", "node", (e) => {
      if (!pinnedRef.current) lit(e.target);
    });
    cy.on("mouseout", "node", () => {
      if (!pinnedRef.current) clear();
    });

    cy.on("tap", "node", (evt) => {
      const n = evt.target as cytoscape.NodeSingular;
      const d = n.data() as GNodeData;
      cy.nodes().removeClass("pinned");
      n.addClass("pinned");
      pinnedRef.current = d.id;
      clear();
      lit(n);
      if (d.isCluster) {
        setInspect({ kind: "cluster", id: d.id, label: d.label, type: d.clusterType ?? "cluster", severity: d.severity, cluster: clusters.get(d.id) });
      } else {
        const neighbors: NonNullable<Inspect["neighbors"]> = [];
        n.connectedEdges().forEach((e: cytoscape.EdgeSingular) => {
          const out = e.data("source") === d.id;
          const other = out ? e.target() : e.source();
          neighbors.push({ label: (other.data("label") as string).replace(/^▸ /, ""), rel: e.data("label"), dir: out ? "out" : "in" });
        });
        setInspect({ kind: "node", id: d.id, label: (d.label as string).replace(/^▸ /, ""), type: d.type, severity: d.severity, neighbors });
      }
    });
    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        pinnedRef.current = null;
        cy.nodes().removeClass("pinned");
        clear();
        setInspect(null);
      }
    });

    return () => {
      cancelAnimationFrame(raf);
      cy.destroy();
      cyRef.current = null;
      pinnedRef.current = null;
    };
  }, [processed]);

  function runSearch(q: string) {
    const cy = cyRef.current;
    if (!cy || !q.trim()) return;
    const needle = q.trim().toLowerCase();
    const hit = cy.nodes().filter((n) => (n.data("label") as string)?.toLowerCase().includes(needle));
    const first = hit[0];
    if (!first) return;
    cy.animate({ center: { eles: first }, zoom: 1.2 }, { duration: 400 });
    cy.nodes().removeClass("pinned");
    first.addClass("pinned");
    pinnedRef.current = first.id();
    cy.elements().removeClass("lit dim").addClass("dim");
    first.closedNeighborhood().removeClass("dim").addClass("lit");
    first.connectedEdges().removeClass("dim").addClass("lit");
    (first.emit as (e: string) => void)("tap");
  }

  if (graphRes.loading && !graphRes.loaded) return <Loading label="Building graph…" />;
  if (graphRes.error) return <ErrorState message={graphRes.error} onRetry={graphRes.refetch} />;
  if (!processed || processed.nodes.length === 0) {
    return (
      <EmptyState
        icon={Network}
        title="No graph yet"
        hint="The attack-surface map is built from relationships Osprey discovers (domain → subdomain → host → service). Run recon from the Chat tab to populate it."
      />
    );
  }

  return (
    <div className="relative h-full">
      {/* Controls */}
      <div className="absolute left-4 top-3 z-10 flex items-center gap-1.5">
        <button onClick={() => cyRef.current?.animate({ fit: { eles: cyRef.current.elements(":visible"), padding: 40 } }, { duration: 350 })} className="btn-outline bg-surface/80 backdrop-blur" title="Fit to view">
          <Maximize2 size={13} /> Fit
        </button>
        <button onClick={() => cyRef.current?.layout(layoutOpts()).run()} className="btn-outline bg-surface/80 backdrop-blur" title="Re-run layout">
          <RefreshCw size={13} /> Relayout
        </button>
        <div className="flex items-center gap-1.5 rounded-lg border border-border-strong bg-surface/80 px-2.5 py-1.5 backdrop-blur">
          <Search size={13} className="text-ink-faint" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && runSearch(query)}
            placeholder="Find…"
            className="w-28 bg-transparent text-[12px] text-ink placeholder:text-ink-faint focus:outline-none"
          />
        </div>
      </div>

      {/* Coverage note */}
      <div className="absolute right-4 top-3 z-[5] rounded-lg border border-border bg-surface/70 px-2.5 py-1 text-[11px] text-ink-faint backdrop-blur">
        {processed.stats.shown} assets
        {processed.stats.collapsed > 0 && ` · ${processed.stats.collapsed} grouped`}
      </div>

      {/* Legend: hierarchy + risk */}
      <div className="absolute bottom-4 left-4 z-10 flex flex-col gap-1.5 rounded-lg border border-border bg-surface/85 px-3 py-2 text-[11px] backdrop-blur">
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-ink-dim">
          <span className="font-medium text-ink-faint">Flow</span>
          <span className="flex items-center gap-1"><Swatch c={TYPE_DOT.domain ?? "#f5a623"} /> domain</span>
          <Arrow />
          <span className="flex items-center gap-1"><Swatch c={TYPE_DOT.host ?? "#7fa7c8"} /> host</span>
          <Arrow />
          <span className="flex items-center gap-1"><Swatch c={TYPE_DOT.service ?? "#4fd1c5"} /> service</span>
          <span className="flex items-center gap-1"><Swatch c={TYPE_DOT.person ?? "#b79af6"} /> identity</span>
          <span className="flex items-center gap-1"><Swatch c={TYPE_DOT.credential ?? "#ff9d5c"} /> secret</span>
        </div>
        <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-ink-faint">
          <span className="font-medium">Risk border</span>
          {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
            <span key={s} className="flex items-center gap-1">
              <span className="h-2.5 w-3.5 rounded-sm border-2" style={{ borderColor: SEV_COLOR[s], background: "#141d31" }} />
              {SEVERITY_META[s].label}
            </span>
          ))}
        </div>
      </div>

      <div ref={containerRef} className="h-full w-full" />

      {/* Inspector */}
      {inspect && (
        <div className="absolute right-4 top-12 z-10 w-80 rounded-xl border border-border bg-surface/95 p-3.5 shadow-lift backdrop-blur">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wider text-ink-faint">
                <Swatch c={TYPE_DOT[inspect.type] ?? "#8696b0"} />
                {inspect.kind === "cluster" ? `${inspect.type} group` : inspect.type}
              </div>
              <div className="mt-0.5 break-all font-mono text-[13px] text-ink">{inspect.label}</div>
            </div>
            <button onClick={() => { setInspect(null); pinnedRef.current = null; cyRef.current?.nodes().removeClass("pinned"); cyRef.current?.elements().removeClass("lit dim"); }} className="btn-ghost p-1">
              <X size={14} />
            </button>
          </div>
          {inspect.severity && inspect.severity !== "none" && (
            <div className="mt-2">
              <span className={cn("inline-flex rounded-full px-2 py-0.5 text-[11px]", SEVERITY_META[inspect.severity].bg, SEVERITY_META[inspect.severity].text)}>
                {SEVERITY_META[inspect.severity].label} severity
              </span>
            </div>
          )}
          {inspect.kind === "cluster" && inspect.cluster ? (
            <>
              <div className="mt-3 text-[11px] font-medium uppercase tracking-wider text-ink-faint">
                {inspect.cluster.members.length} {inspect.type === "url" ? "endpoints" : inspect.type}
              </div>
              <div className="mt-1 max-h-72 space-y-0.5 overflow-y-auto">
                {inspect.cluster.members.map((m) => (
                  <div key={m.id} className="flex items-center gap-1.5 text-[12px]" title={m.label}>
                    {m.severity && m.severity !== "none" && <span className="h-1.5 w-1.5 flex-none rounded-full" style={{ background: SEV_COLOR[m.severity] }} />}
                    <span className="truncate font-mono text-ink-dim">{m.label}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <>
              <div className="mt-3 text-[11px] font-medium uppercase tracking-wider text-ink-faint">
                Connections ({inspect.neighbors?.length ?? 0})
              </div>
              <div className="mt-1 max-h-72 space-y-1 overflow-y-auto">
                {inspect.neighbors?.map((nb, i) => (
                  <div key={i} className="flex items-center gap-1.5 text-[12px] text-ink-dim">
                    <span className="font-mono text-[10px] text-ink-faint">{nb.dir === "out" ? "→" : "←"}</span>
                    <span className="text-ink-faint">{nb.rel}</span>
                    <span className="truncate font-mono text-ink-dim">{nb.label}</span>
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function Swatch({ c }: { c: string }) {
  return <span className="h-2 w-2 flex-none rounded-full" style={{ background: c }} />;
}
function Arrow() {
  return <span className="text-ink-faint">›</span>;
}
