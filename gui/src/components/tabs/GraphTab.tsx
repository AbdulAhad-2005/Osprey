"use client";

import { useEffect, useRef, useState } from "react";
import cytoscape, { type Core } from "cytoscape";
import { Maximize2, RefreshCw, Network, X } from "lucide-react";
import { getGraph } from "@/lib/api";
import { useResource } from "@/hooks/useResource";
import type { CytoGraph, Severity } from "@/lib/types";
import { SEVERITY_META } from "@/lib/format";
import { cn } from "@/lib/cn";
import { Loading, EmptyState, ErrorState } from "@/components/ui/States";

const TYPE_COLOR: Record<string, string> = {
  domain: "#f5a623",
  subdomain: "#38bdf8",
  host: "#6c7e9e",
  ip: "#6c7e9e",
  port: "#22d3ee",
  service: "#a78bfa",
  technology: "#35c08f",
  email: "#c084fc",
  person: "#c084fc",
  username: "#c084fc",
  phone: "#c084fc",
  credential: "#f5a623",
  secret: "#f5a623",
};
const SEV_COLOR: Record<string, string> = {
  critical: "#ff5d6c",
  high: "#ff8a4c",
  medium: "#ffc53d",
  low: "#5eb0ef",
};

function buildStyle(): cytoscape.Stylesheet[] {
  const typeRules = Object.entries(TYPE_COLOR).map(([t, c]) => ({
    selector: `node[type = "${t}"]`,
    style: { "background-color": c, "border-color": c },
  }));
  const sevRules = Object.entries(SEV_COLOR).map(([s, c]) => ({
    selector: `node[severity = "${s}"]`,
    style: { "background-color": c, "border-color": c },
  }));
  return [
    {
      selector: "node",
      style: {
        "background-color": "#3d4d6b",
        "border-color": "#3d4d6b",
        "border-width": 1.5,
        width: 16,
        height: 16,
        label: "data(label)",
        color: "#c3cbdb",
        "font-size": 8.5,
        "font-family": "var(--font-mono, monospace)",
        "text-valign": "bottom",
        "text-margin-y": 3,
        "text-halign": "center",
        "text-wrap": "ellipsis",
        "text-max-width": "90px",
        "min-zoomed-font-size": 6,
      },
    },
    { selector: 'node[type = "domain"]', style: { shape: "round-rectangle", width: 24, height: 24, "font-size": 10 } },
    { selector: 'node[type = "subdomain"]', style: { shape: "round-rectangle" } },
    { selector: 'node[type = "port"]', style: { shape: "hexagon" } },
    { selector: 'node[type = "service"]', style: { shape: "diamond" } },
    { selector: 'node[type = "technology"]', style: { shape: "tag" } },
    ...typeRules,
    ...sevRules,
    {
      selector: "node:selected",
      style: { "border-width": 3, "border-color": "#f5a623", "font-size": 11, color: "#e8edf6" },
    },
    {
      selector: "edge",
      style: {
        width: 1.2,
        "line-color": "#2d3d59",
        "target-arrow-color": "#2d3d59",
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.8,
        "curve-style": "bezier",
        label: "data(label)",
        "font-size": 7,
        color: "#5d6b83",
        "text-rotation": "autorotate",
        "min-zoomed-font-size": 7,
      },
    },
    { selector: "edge[?hypothesis]", style: { "line-style": "dashed", "line-color": "#c47d10", "target-arrow-color": "#c47d10" } },
    { selector: "node.faded", style: { opacity: 0.22 } },
    { selector: "edge.faded", style: { opacity: 0.1 } },
  ];
}

interface SelectedNode {
  id: string;
  label: string;
  type: string;
  severity: Severity;
  neighbors: { label: string; rel: string; dir: "out" | "in" }[];
}

export function GraphTab({ engagementId }: { engagementId: string }) {
  const graphRes = useResource((s) => getGraph(engagementId, s), [engagementId]);
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const [selected, setSelected] = useState<SelectedNode | null>(null);

  const graph = graphRes.data;

  useEffect(() => {
    if (!containerRef.current || !graph || graph.nodes.length === 0) return;
    const hasDomain = graph.nodes.some((n) => n.data.type === "domain");
    const cy = cytoscape({
      container: containerRef.current,
      elements: { nodes: graph.nodes, edges: graph.edges },
      style: buildStyle(),
      layout: {
        name: "breadthfirst",
        directed: true,
        padding: 28,
        spacingFactor: 1.15,
        animate: false,
        ...(hasDomain ? { roots: 'node[type = "domain"]' } : {}),
      } as cytoscape.LayoutOptions,
      wheelSensitivity: 0.25,
      minZoom: 0.2,
      maxZoom: 2.5,
    });
    cyRef.current = cy;

    cy.on("tap", "node", (evt) => {
      const n = evt.target;
      const d = n.data();
      const neighbors: SelectedNode["neighbors"] = [];
      n.connectedEdges().forEach((e: cytoscape.EdgeSingular) => {
        const out = e.data("source") === d.id;
        const other = out ? e.target() : e.source();
        neighbors.push({ label: other.data("label"), rel: e.data("label"), dir: out ? "out" : "in" });
      });
      setSelected({ id: d.id, label: d.label, type: d.type, severity: d.severity, neighbors });
      cy.elements().addClass("faded");
      n.removeClass("faded");
      n.neighborhood().removeClass("faded");
      n.connectedEdges().removeClass("faded");
    });
    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        setSelected(null);
        cy.elements().removeClass("faded");
      }
    });

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph]);

  if (graphRes.loading && !graphRes.loaded) return <Loading label="Building graph…" />;
  if (graphRes.error) return <ErrorState message={graphRes.error} onRetry={graphRes.refetch} />;
  if (!graph || graph.nodes.length === 0) {
    return (
      <EmptyState
        icon={Network}
        title="No graph yet"
        hint="The attack-surface graph is built from relationships Osprey discovers (domain → subdomain → host → port → service). Run recon from the Chat tab to populate it."
      />
    );
  }

  return (
    <div className="relative h-full">
      {/* Controls */}
      <div className="absolute left-4 top-3 z-10 flex items-center gap-1.5">
        <button onClick={() => cyRef.current?.fit(undefined, 40)} className="btn-outline bg-surface/80 backdrop-blur" title="Fit to view">
          <Maximize2 size={13} /> Fit
        </button>
        <button
          onClick={() => cyRef.current?.layout({ name: "breadthfirst", directed: true, padding: 28, spacingFactor: 1.15, animate: true } as cytoscape.LayoutOptions).run()}
          className="btn-outline bg-surface/80 backdrop-blur"
          title="Re-run layout"
        >
          <RefreshCw size={13} /> Layout
        </button>
      </div>

      {/* Legend */}
      <div className="absolute bottom-4 left-4 z-10 rounded-lg border border-border bg-surface/85 px-3 py-2 text-[11px] backdrop-blur">
        <div className="mb-1 font-medium text-ink-dim">Severity</div>
        <div className="flex flex-wrap gap-x-3 gap-y-1">
          {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
            <span key={s} className="flex items-center gap-1.5 text-ink-faint">
              <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLOR[s] }} />
              {SEVERITY_META[s].label}
            </span>
          ))}
          <span className="flex items-center gap-1.5 text-ink-faint">
            <span className="h-0 w-3 border-t border-dashed" style={{ borderColor: "#c47d10" }} /> hypothesis
          </span>
        </div>
      </div>

      {/* Graph canvas */}
      <div ref={containerRef} className="h-full w-full" />

      {/* Inspector */}
      {selected && (
        <div className="absolute right-4 top-3 z-10 w-72 rounded-xl border border-border bg-surface/95 p-3.5 shadow-lift backdrop-blur">
          <div className="flex items-start justify-between gap-2">
            <div>
              <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wider text-ink-faint">
                <span className="h-2 w-2 rounded-full" style={{ background: SEV_COLOR[selected.severity] ?? TYPE_COLOR[selected.type] ?? "#3d4d6b" }} />
                {selected.type}
              </div>
              <div className="mt-0.5 break-all font-mono text-[13px] text-ink">{selected.label}</div>
            </div>
            <button onClick={() => { setSelected(null); cyRef.current?.elements().removeClass("faded"); }} className="btn-ghost p-1">
              <X size={14} />
            </button>
          </div>
          {selected.severity && selected.severity !== "none" && (
            <div className="mt-2">
              <span className={cn("inline-flex rounded-full px-2 py-0.5 text-[11px]", SEVERITY_META[selected.severity].bg, SEVERITY_META[selected.severity].text)}>
                {SEVERITY_META[selected.severity].label} severity
              </span>
            </div>
          )}
          <div className="mt-3 text-[11px] font-medium uppercase tracking-wider text-ink-faint">
            Relationships ({selected.neighbors.length})
          </div>
          <div className="mt-1 max-h-60 space-y-1 overflow-y-auto">
            {selected.neighbors.map((nb, i) => (
              <div key={i} className="flex items-center gap-1.5 text-[12px] text-ink-dim">
                <span className="font-mono text-[10px] text-ink-faint">{nb.dir === "out" ? "→" : "←"}</span>
                <span className="text-ink-faint">{nb.rel}</span>
                <span className="truncate font-mono text-ink-dim">{nb.label}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
