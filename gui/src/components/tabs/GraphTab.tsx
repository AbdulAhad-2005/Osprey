"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import cytoscape, { type Core } from "cytoscape";
import dagre from "cytoscape-dagre";
import {
  Maximize2,
  RefreshCw,
  Network,
  X,
  Search,
  List,
  Download,
  Expand,
  Minimize2,
  ArrowLeft,
  Plus,
  Minus,
} from "lucide-react";
import { getGraph } from "@/lib/api";
import { useResource } from "@/hooks/useResource";
import { useWorkspace } from "@/components/shell/WorkspaceProvider";
import type { Severity } from "@/lib/types";
import {
  processGraph,
  graphNeighborhood,
  responsiveLayout,
  type Cluster,
  type GNodeData,
} from "@/lib/graphModel";
import {
  engagementOverview,
  overviewPositions,
  neighborhoodPositions,
  TYPE_LABELS,
} from "@/lib/graphExplorer";
import { useSearchParams } from "next/navigation";
import { SEVERITY_META } from "@/lib/format";
import { cn } from "@/lib/cn";
import { Loading, EmptyState, ErrorState } from "@/components/ui/States";
import { RecordInspector } from "@/components/ui/RecordInspector";
import type { RecordReference } from "@/lib/types";

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
  info: "#94a3b8",
};

function dot(d: GNodeData): string {
  return (
    TYPE_DOT[d.isCluster ? (d.clusterType ?? "cluster") : d.type] ?? "#8696b0"
  );
}
function bg(d: GNodeData): string {
  if (d.primary) return "#7a5415";
  return (
    TYPE_BG[d.isCluster ? (d.clusterType ?? "cluster") : d.type] ?? "#222a39"
  );
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
        width: 180,
        height: 48,
        padding: "8px",
        label: "data(label)",
        color: "#dbe2ee",
        "font-size": 14,
        "font-family":
          "ui-monospace, 'JetBrains Mono', SFMono-Regular, Menlo, monospace",
        "text-valign": "center",
        "text-halign": "center",
        "text-wrap": "wrap",
        "text-max-width": "170px",
        "min-zoomed-font-size": 0,
      } as unknown as cytoscape.Css.Node,
    },
    {
      selector: "node[primaryFlag = 1]",
      style: {
        color: "#fff6e6",
        "font-size": 13,
        "font-weight": 700,
        height: 34,
      },
    },
    {
      selector: 'node[kind = "domain"]',
      style: { "font-size": 12, "font-weight": 600, height: 30 },
    },
    {
      selector: "node[isClusterFlag = 1]",
      style: {
        "font-style": "italic",
        color: "#aeb8c9",
        "border-style": "dashed",
      },
    },
    { selector: "node.dim", style: { opacity: 0.2 } },
    { selector: "node.hidden", style: { display: "none" } },
    {
      selector: "node.lit",
      style: {
        "border-color": "#f5a623",
        "border-width": 2.5,
        "z-index": 30,
        color: "#fff",
      },
    },
    {
      selector: "node.pinned, node[focusFlag = 1]",
      style: { "border-color": "#f5a623", "border-width": 3 },
    },
    {
      selector: "node[overviewFlag = 1]",
      style: {
        width: 180,
        height: 76,
        "font-size": 17,
        "text-wrap": "wrap",
        "font-style": "normal",
        "border-style": "solid",
        "text-max-width": "180px",
      },
    },
    {
      selector: "edge",
      style: {
        width: 1.3,
        "line-color": "#30415f",
        "target-arrow-color": "#30415f",
        "target-arrow-shape": "triangle",
        "arrow-scale": 0.8,
        "curve-style": "bezier",
        label: "",
      },
    },
    {
      selector: "edge[detailFlag = 1], edge:selected, edge.lit",
      style: {
        label: "data(label)",
        "font-size": 11,
        color: "#bcc9db",
        "text-background-color": "#0b1020",
        "text-background-opacity": 0.95,
        "text-background-padding": "4px",
        "text-rotation": "autorotate",
      } as cytoscape.Css.Edge,
    },
    {
      selector: "edge[hypothesisFlag = 1]",
      style: {
        "line-style": "dashed",
        "line-color": "#c47d10",
        "target-arrow-color": "#c47d10",
      },
    },
    {
      selector: "edge.lit",
      style: {
        "line-color": "#6f86ad",
        "target-arrow-color": "#6f86ad",
        width: 2,
        "z-index": 25,
      },
    },
    { selector: "edge.dim", style: { opacity: 0.08 } },
    { selector: "edge.hidden", style: { display: "none" } },
  ];
}

function layoutOpts(name = "dagre"): cytoscape.LayoutOptions {
  if (name !== "dagre")
    return {
      name,
      fit: true,
      padding: 30,
      animate: false,
    } as cytoscape.LayoutOptions;
  return {
    name: "dagre",
    rankDir: "LR",
    nodeSep: 16,
    rankSep: 70,
    edgeSep: 8,
    ranker: "network-simplex",
    animate: false,
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
  neighbors?: { id: string; label: string; rel: string; dir: "out" | "in" }[];
  cluster?: Cluster;
}

// Prefix the label with a small swatch glyph so the type colour reads inside the
// box without an extra DOM layer. ◆ tinted via a leading space keeps it subtle.
function labelWith(d: GNodeData): string {
  const base = d.label.length > 40 ? d.label.slice(0, 39) + "…" : d.label;
  return d.isCluster ? `▸ ${base}` : `${d.type.toUpperCase()}\n${base}`;
}

export function GraphTab({ engagementId }: { engagementId: string }) {
  const searchParams = useSearchParams();
  const { engagements } = useWorkspace();
  const primaryTarget = engagements.find(
    (engagement) => engagement.id === engagementId,
  )?.target;
  const graphRes = useResource(
    (s) => getGraph(engagementId, s),
    [engagementId],
  );
  const containerRef = useRef<HTMLDivElement>(null);
  const frameRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);
  const cameraRef = useRef<{
    key: string;
    zoom: number;
    pan: { x: number; y: number };
  } | null>(null);
  const pinnedRef = useRef<string | null>(null);
  const appliedAssetRef = useRef("");
  const [inspect, setInspect] = useState<Inspect | null>(null);
  const [query, setQuery] = useState("");
  const [focus, setFocus] = useState("");
  const [fullMap, setFullMap] = useState(false);
  const [fullscreen, setFullscreen] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [hops, setHops] = useState(1);
  const [edgeInspect, setEdgeInspect] = useState<string | null>(null);
  const [memberQuery, setMemberQuery] = useState("");
  const [memberPage, setMemberPage] = useState(0);
  const [edgePage, setEdgePage] = useState(0);
  const [relationshipQuery, setRelationshipQuery] = useState("");
  const [group, setGroup] = useState(true);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [browse, setBrowse] = useState(false);
  const [assetType, setAssetType] = useState("");
  const [assetPage, setAssetPage] = useState(0);
  const [layout, setLayout] = useState("dagre");
  const [evidence, setEvidence] = useState<RecordReference | null>(null);
  const [searchMessage, setSearchMessage] = useState("");
  const isOverview = !focus && !fullMap;
  const scopedGraph = useMemo(
    () =>
      graphRes.data &&
      (focus ? graphNeighborhood(graphRes.data, focus, hops) : graphRes.data),
    [graphRes.data, focus, hops],
  );

  const processed = useMemo(() => {
    if (!scopedGraph) return null;
    if (isOverview) return engagementOverview(scopedGraph);
    const graph = processGraph(scopedGraph, primaryTarget, {
      group,
      expanded: new Set([...expanded, focus]),
    });
    return graph;
  }, [scopedGraph, focus, fullMap, primaryTarget, isOverview, group, expanded]);

  const nodeIndex = useMemo(
    () =>
      new Map(
        graphRes.data?.nodes.map((node) => [node.data.id, node.data]) || [],
      ),
    [graphRes.data],
  );
  const effectiveLayout = responsiveLayout(
    layout,
    processed?.nodes.length || 0,
  );
  const selectedEdges = useMemo(
    () =>
      (edgeInspect === "all"
        ? scopedGraph?.edges.map((_, index) => index) || []
        : processed?.edges.find((e) => e.data.id === edgeInspect)?.data
            .records || []
      )
        .map((index) => scopedGraph?.edges[index])
        .filter((edge): edge is NonNullable<typeof edge> => !!edge),
    [processed, edgeInspect, scopedGraph],
  );
  const filteredEdges = useMemo(
    () =>
      selectedEdges.filter(({ data }) =>
        `${data.label} ${nodeIndex.get(data.source)?.label} ${nodeIndex.get(data.target)?.label}`
          .toLowerCase()
          .includes(relationshipQuery.toLowerCase()),
      ),
    [selectedEdges, nodeIndex, relationshipQuery],
  );
  const relationCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const { data } of selectedEdges)
      counts.set(data.label, (counts.get(data.label) || 0) + 1);
    return [...counts].sort((a, b) => b[1] - a[1]);
  }, [selectedEdges]);
  const matches = useMemo(
    () =>
      (graphRes.data?.nodes || []).filter(
        (node) =>
          (!assetType || node.data.type === assetType) &&
          `${node.data.label} ${node.data.type} ${node.data.source_tools?.join(" ") || ""}`
            .toLowerCase()
            .includes(query.trim().toLowerCase()),
      ),
    [graphRes.data, query, assetType],
  );

  function inspectNode(id: string) {
    const node = nodeIndex.get(id);
    if (!node) return;
    const neighbors: NonNullable<Inspect["neighbors"]> = [];
    for (const edge of graphRes.data?.edges || []) {
      if (edge.data.source !== id && edge.data.target !== id) continue;
      const out = edge.data.source === id;
      const otherId = out ? edge.data.target : edge.data.source;
      neighbors.push({
        id: otherId,
        label: nodeIndex.get(otherId)?.label || otherId,
        rel: edge.data.label,
        dir: out ? "out" : "in",
      });
    }
    setEdgeInspect(null);
    setInspect({
      kind: "node",
      id,
      label: node.label,
      type: node.type,
      severity: node.severity,
      neighbors,
    });
  }

  function focusNode(id: string) {
    if (id === focus) return;
    setHistory((previous) => [...previous, focus]);
    setFocus(id);
    setLayout("neighborhood");
    inspectNode(id);
    setBrowse(false);
  }

  useEffect(() => {
    const asset = searchParams.get("asset");
    if (!asset || !graphRes.data) return;
    const intentKey = `${engagementId}:${asset}`;
    if (appliedAssetRef.current === intentKey) return;
    appliedAssetRef.current = intentKey;
    const match = graphRes.data.nodes.find(
      ({ data }) =>
        data.id === asset || data.label.toLowerCase() === asset.toLowerCase(),
    );
    if (match) {
      setFocus(match.data.id);
      setLayout("neighborhood");
      inspectNode(match.data.id);
    } else {
      setQuery(asset);
      setBrowse(true);
      setSearchMessage(
        "No exact stored asset matches this target. Search related assets below.",
      );
    }
  }, [searchParams, graphRes.data]);

  useEffect(() => {
    const onEscape = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !document.querySelector("dialog[open]"))
        setFullscreen(false);
    };
    const onChange = () => {
      if (!document.fullscreenElement) setFullscreen(false);
    };
    document.addEventListener("keydown", onEscape);
    document.addEventListener("fullscreenchange", onChange);
    return () => {
      document.removeEventListener("keydown", onEscape);
      document.removeEventListener("fullscreenchange", onChange);
    };
  }, []);

  async function toggleFullscreen() {
    if (fullscreen) {
      if (document.fullscreenElement) await document.exitFullscreen();
      setFullscreen(false);
    } else {
      setFullscreen(true);
      // Embedded browsers may deny native fullscreen; the viewport fallback
      // still removes the app chrome and remains escapable.
      try {
        await frameRef.current?.requestFullscreen?.();
      } catch {
        /* viewport fallback */
      }
    }
  }

  useEffect(() => {
    if (!containerRef.current || !processed || processed.nodes.length === 0)
      return;
    ensureDagre();
    const clusters = processed.clusters;
    const cameraKey = JSON.stringify([
      focus,
      fullMap,
      group,
      hops,
      effectiveLayout,
      [...expanded],
    ]);

    const nodes = processed.nodes.map((n) => {
      const sev =
        n.data.severity && n.data.severity !== "none" ? n.data.severity : null;
      return {
        data: {
          ...n.data,
          bg: bg(n.data),
          dot: dot(n.data),
          fullLabel: n.data.label,
          label: isOverview ? n.data.label : labelWith(n.data),
          ring: sev ? 2.5 : 1,
          ringColor: SEV_COLOR[sev || "none"] ?? "rgba(120,140,175,0.35)",
          isClusterFlag: n.data.isCluster ? 1 : 0,
          primaryFlag: n.data.primary ? 1 : 0,
          kind: n.data.type,
          overviewFlag: isOverview ? 1 : 0,
          focusFlag: n.data.id === focus ? 1 : 0,
        },
      };
    });
    const edges = processed.edges.map((e) => {
      return {
        data: {
          id: e.data.id,
          source: e.data.source,
          target: e.data.target,
          label: e.data.label.replaceAll("_", " "),
          hypothesisFlag: e.data.hypothesis ? 1 : 0,
          overviewFlag: isOverview ? 1 : 0,
          detailFlag: !isOverview && processed.nodes.length <= 40 ? 1 : 0,
        },
      };
    });

    const cy = cytoscape({
      container: containerRef.current,
      elements: { nodes, edges },
      style: buildStyle(),
      layout: isOverview
        ? {
            name: "preset",
            positions: overviewPositions(processed.nodes),
            fit: true,
            padding: 55,
          }
        : effectiveLayout === "neighborhood" &&
            focus &&
            processed.nodes.length <= 40
          ? {
              name: "preset",
              positions: neighborhoodPositions(processed.nodes, focus),
              fit: true,
              padding: 35,
            }
          : layoutOpts(
              effectiveLayout === "neighborhood" ? "grid" : effectiveLayout,
            ),
      wheelSensitivity: 0.2,
      minZoom: 0.015,
      maxZoom: 2.5,
      pixelRatio: 1,
    });
    cyRef.current = cy;

    const fitAll = () => cy.fit(cy.elements(":visible"), 40);
    const readableCenter = () => {
      const target = cy.getElementById(focus) || cy.collection();
      const center = target.length
        ? target
        : cy.nodes().filter((node) => !!node.data("primary"));
      if (center.length) {
        cy.zoom(Math.max(cy.zoom(), 0.65));
        cy.center(center.first());
      }
    };
    cy.one("layoutstop", () => {
      cy.resize();
      fitAll();
      if (processed.nodes.length > 40) readableCenter();
    });
    const raf = requestAnimationFrame(() => {
      cy.resize();
      if (cameraRef.current?.key === cameraKey) {
        cy.viewport({
          zoom: cameraRef.current.zoom,
          pan: cameraRef.current.pan,
        });
      } else {
        fitAll();
        if (processed.nodes.length > 40) readableCenter();
      }
    });
    let priorSize = `${containerRef.current.clientWidth}:${containerRef.current.clientHeight}`;
    const resize = new ResizeObserver(() => {
      const size = `${containerRef.current?.clientWidth}:${containerRef.current?.clientHeight}`;
      cy.resize();
      if (size !== priorSize && (isOverview || processed.nodes.length <= 40))
        cy.fit(cy.elements(), 40);
      priorSize = size;
    });
    resize.observe(containerRef.current);

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
    cy.on("mouseover", "edge", (event) => event.target.addClass("lit"));
    cy.on("mouseout", "edge", (event) => event.target.removeClass("lit"));

    cy.on("tap", "node", (evt) => {
      const n = evt.target as cytoscape.NodeSingular;
      const d = n.data() as GNodeData;
      cy.nodes().removeClass("pinned");
      n.addClass("pinned");
      pinnedRef.current = d.id;
      clear();
      lit(n);
      if (d.isCluster) {
        setMemberQuery("");
        setMemberPage(0);
        setEdgeInspect(null);
        setInspect({
          kind: "cluster",
          id: d.id,
          label: d.label,
          type: d.clusterType ?? "cluster",
          severity: d.severity,
          cluster: clusters.get(d.id),
        });
      } else {
        inspectNode(d.id);
      }
    });
    cy.on("tap", "edge", (evt) => {
      setInspect(null);
      setEdgePage(0);
      setRelationshipQuery("");
      setEdgeInspect(evt.target.id());
    });
    cy.on("tap", (evt) => {
      if (evt.target === cy) {
        pinnedRef.current = null;
        cy.nodes().removeClass("pinned");
        clear();
        setInspect(null);
        setEdgeInspect(null);
      }
    });

    return () => {
      cancelAnimationFrame(raf);
      resize.disconnect();
      cameraRef.current = { key: cameraKey, zoom: cy.zoom(), pan: cy.pan() };
      cy.destroy();
      cyRef.current = null;
      pinnedRef.current = null;
    };
  }, [processed, effectiveLayout, isOverview]);

  function runSearch(q: string) {
    if (!q.trim()) return;
    if (matches.length === 1 && matches[0]) focusNode(matches[0].data.id);
    else {
      setBrowse(true);
      setSearchMessage(
        `${matches.length} matching assets. Choose one from the asset browser.`,
      );
    }
  }

  function downloadGraph() {
    const href = URL.createObjectURL(
      new Blob([JSON.stringify(graphRes.data, null, 2)], {
        type: "application/json",
      }),
    );
    const link = document.createElement("a");
    link.href = href;
    link.download = `osprey-graph-${engagementId}.json`;
    link.click();
    URL.revokeObjectURL(href);
  }

  if (graphRes.loading && !graphRes.loaded)
    return <Loading label="Building graph…" />;
  if (graphRes.error)
    return <ErrorState message={graphRes.error} onRetry={graphRes.refetch} />;
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
    <div
      ref={frameRef}
      className={cn(
        "flex h-full flex-col bg-base",
        fullscreen && "fixed inset-0 z-[100]",
      )}
    >
      {/* Controls */}
      <div className="flex flex-wrap items-center gap-2 border-b border-border bg-surface/50 px-4 py-3">
        <button
          className="btn-outline"
          disabled={!history.length && !focus}
          aria-label="Back to previous graph view"
          onClick={() => {
            const previous = history[history.length - 1] || "";
            setHistory(history.slice(0, -1));
            setFocus(previous);
            setInspect(null);
            setEdgeInspect(null);
          }}
        >
          <ArrowLeft size={14} />
        </button>
        <button
          onClick={() => setBrowse(!browse)}
          className="btn-outline"
          aria-expanded={browse}
        >
          <List size={13} /> Browse assets
        </button>
        <select
          aria-label="Graph view"
          value={focus ? "focus" : fullMap ? "map" : "overview"}
          onChange={(e) => {
            setFullMap(e.target.value !== "overview");
            setFocus("");
            setInspect(null);
            setEdgeInspect(null);
            setHistory([]);
            setSearchMessage("");
          }}
          className="rounded-lg border border-border bg-surface px-2 py-1.5 text-xs"
        >
          <option value="overview">Engagement overview</option>
          <option value="map">Detailed topology</option>
          {focus && <option value="focus">Focused connections</option>}
        </select>
        {!isOverview && (
          <label className="flex items-center gap-1.5 text-xs text-ink-dim">
            <input
              type="checkbox"
              checked={group}
              onChange={(e) => {
                setGroup(e.target.checked);
                setInspect(null);
              }}
            />{" "}
            Group equivalent assets
          </label>
        )}
        {!isOverview && (
          <select
            aria-label="Graph layout"
            value={layout}
            onChange={(e) => setLayout(e.target.value)}
            className="rounded-lg border border-border bg-surface px-2 py-1.5 text-xs"
          >
            <option value="neighborhood">Balanced</option>
            <option value="dagre">Hierarchy</option>
            <option value="concentric">Radial</option>
            <option value="grid">Grid</option>
          </select>
        )}
        {focus && (
          <select
            aria-label="Connection depth"
            className="rounded-lg border border-border bg-surface px-2 py-1.5 text-xs"
            value={hops}
            onChange={(e) => setHops(Number(e.target.value))}
          >
            <option value={1}>Direct connections</option>
            <option value={2}>Two hops</option>
          </select>
        )}
        <button
          onClick={() =>
            cyRef.current?.animate(
              {
                fit: { eles: cyRef.current.elements(":visible"), padding: 40 },
              },
              { duration: 350 },
            )
          }
          className="btn-outline bg-surface/80 backdrop-blur"
          title="Fit to view"
        >
          <Maximize2 size={13} /> Fit all
        </button>
        {!isOverview && (
          <button
            className="btn-outline"
            onClick={() => {
              const cy = cyRef.current;
              if (!cy) return;
              const target = focus
                ? cy.getElementById(focus)
                : cy
                    .nodes()
                    .filter((node) => !!node.data("primary"))
                    .first();
              if (target.length) {
                cy.zoom(0.8);
                cy.center(target);
              }
            }}
          >
            Recenter
          </button>
        )}
        <button className="btn-outline" onClick={toggleFullscreen}>
          {fullscreen ? <Minimize2 size={14} /> : <Expand size={14} />}{" "}
          {fullscreen ? "Exit fullscreen" : "Fullscreen"}
        </button>
        <button
          onClick={() => graphRes.refetch()}
          className="btn-outline bg-surface/80 backdrop-blur"
          title="Refresh graph evidence"
        >
          <RefreshCw size={13} /> Refresh
        </button>
        <button
          onClick={downloadGraph}
          className="btn-outline"
          title="Download all loaded graph records and provenance"
        >
          <Download size={13} /> JSON
        </button>
        <button
          className="btn-outline"
          onClick={() => {
            setInspect(null);
            setEdgeInspect("all");
            setEdgePage(0);
            setRelationshipQuery("");
          }}
        >
          Relationships
        </button>
        <div className="flex items-center gap-1.5 rounded-lg border border-border-strong bg-surface/80 px-2.5 py-1.5 backdrop-blur">
          <Search size={13} className="text-ink-faint" />
          <input
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setAssetPage(0);
              if (e.target.value) setBrowse(true);
            }}
            onKeyDown={(e) => e.key === "Enter" && runSearch(query)}
            placeholder="Search all assets…"
            aria-label="Search all graph assets"
            className="w-40 bg-transparent text-[12px] text-ink placeholder:text-ink-faint focus:outline-none"
          />
        </div>
      </div>

      <div className="border-b border-border px-4 py-2 text-xs text-ink-dim">
        {!isOverview && effectiveLayout !== layout && (
          <p className="mb-1 text-amber-soft">
            Large-map grid layout keeps all records available without blocking
            the browser. Focus on an asset to use hierarchy.
          </p>
        )}
        {focus
          ? `${hops === 1 ? "Direct" : "Two-hop"} connections · ${nodeIndex.get(focus)?.label || focus}. Select a node to inspect it, or follow a connection from its details.`
          : fullMap
            ? "All loaded assets are represented. Pan/zoom the map or choose an asset to follow its connections. Recenter restores readable scale; Fit all shows the whole topology."
            : "Every loaded record is included. Select a category to browse its members; select an arrow for its relationships. Counts are stored asset records, not unique hosts or vulnerabilities."}
        {searchMessage && (
          <p className="mt-1 text-amber-soft">{searchMessage}</p>
        )}
        {graphRes.data?.meta?.truncated && (
          <p className="mt-1 text-amber-soft">
            Server display limit reached ({graphRes.data.meta.node_limit} nodes
            / {graphRes.data.meta.edge_limit} edges). This graph is not the
            entire engagement store.
          </p>
        )}
      </div>
      <div className="relative flex min-h-0 flex-1">
        <aside
          className={cn(
            "flex-none flex-col border-r border-border bg-surface",
            browse
              ? "absolute inset-y-0 left-0 z-20 flex w-72 shadow-lift"
              : "hidden",
          )}
          aria-label="Graph asset browser"
        >
          <div className="flex items-center justify-between gap-2 p-3 text-xs">
            <strong>{matches.length.toLocaleString()} matching assets</strong>
            <button
              onClick={() => setBrowse(false)}
              className="btn-ghost p-1"
              aria-label="Close asset browser"
            >
              <X size={14} />
            </button>
          </div>
          <select
            aria-label="Graph asset type"
            value={assetType}
            onChange={(e) => {
              setAssetType(e.target.value);
              setAssetPage(0);
            }}
            className="mx-3 mb-3 rounded border border-border bg-base p-2 text-xs"
          >
            <option value="">Every asset type</option>
            {[...new Set(graphRes.data?.nodes.map((node) => node.data.type))]
              .sort()
              .map((type) => (
                <option key={type} value={type}>
                  {type}
                </option>
              ))}
          </select>
          <div className="min-h-0 flex-1 overflow-y-auto px-2">
            {matches
              .slice(assetPage * 50, (assetPage + 1) * 50)
              .map(({ data }) => (
                <button
                  key={data.id}
                  onClick={() => focusNode(data.id)}
                  className="mb-1 block w-full rounded-lg border border-transparent p-2 text-left hover:border-border hover:bg-white/5"
                >
                  <span className="block text-[10px] uppercase text-ink-faint">
                    {data.type} · {data.confidence || "confidence not recorded"}
                  </span>
                  <span className="block break-all font-mono text-xs text-ink">
                    {data.label || data.id}
                  </span>
                </button>
              ))}
          </div>
          <div className="flex justify-between border-t border-border p-2 text-xs">
            <button
              className="btn-ghost"
              disabled={!assetPage}
              onClick={() => setAssetPage(assetPage - 1)}
            >
              Previous
            </button>
            <span className="self-center">
              {assetPage + 1}/{Math.max(1, Math.ceil(matches.length / 50))}
            </span>
            <button
              className="btn-ghost"
              disabled={(assetPage + 1) * 50 >= matches.length}
              onClick={() => setAssetPage(assetPage + 1)}
            >
              Next
            </button>
          </div>
        </aside>
        <div className="relative min-w-0 flex-1">
          <div className="absolute left-3 top-3 z-10 flex gap-1">
            <button
              className="btn-outline"
              aria-label="Zoom in"
              onClick={() => {
                const cy = cyRef.current;
                if (cy)
                  cy.zoom({
                    level: cy.zoom() * 1.25,
                    renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
                  });
              }}
            >
              <Plus size={15} />
            </button>
            <button
              className="btn-outline"
              aria-label="Zoom out"
              onClick={() => {
                const cy = cyRef.current;
                if (cy)
                  cy.zoom({
                    level: cy.zoom() / 1.25,
                    renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 },
                  });
              }}
            >
              <Minus size={15} />
            </button>
          </div>
          {/* Coverage note */}
          <div className="absolute right-3 top-3 z-[5] rounded-lg border border-border bg-surface/85 px-2.5 py-1 text-[11px] text-ink-faint backdrop-blur">
            {graphRes.data?.nodes.length.toLocaleString()} loaded records ·{" "}
            {processed.nodes
              .reduce((count, node) => count + (node.data.count || 1), 0)
              .toLocaleString()}{" "}
            represented · {scopedGraph?.edges.length.toLocaleString()} links in
            view
          </div>

          {/* Legend: hierarchy + risk */}
          <div className="absolute bottom-3 left-3 z-10 flex flex-col gap-1.5 rounded-lg border border-border bg-surface/85 px-3 py-2 text-[11px] backdrop-blur">
            <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-ink-dim">
              <span className="font-medium text-ink-faint">Asset types</span>
              <span className="flex items-center gap-1">
                <Swatch c={TYPE_DOT.domain ?? "#f5a623"} /> domain
              </span>
              <span className="flex items-center gap-1">
                <Swatch c={TYPE_DOT.host ?? "#7fa7c8"} /> host
              </span>
              <span className="flex items-center gap-1">
                <Swatch c={TYPE_DOT.service ?? "#4fd1c5"} /> service
              </span>
              <span className="flex items-center gap-1">
                <Swatch c={TYPE_DOT.person ?? "#b79af6"} /> identity
              </span>
              <span className="flex items-center gap-1">
                <Swatch c={TYPE_DOT.credential ?? "#ff9d5c"} /> secret
              </span>
            </div>
            <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 text-ink-faint">
              <span className="font-medium">
                Associated finding severity · dashed links = hypothesis
              </span>
              {(["critical", "high", "medium", "low"] as Severity[]).map(
                (s) => (
                  <span key={s} className="flex items-center gap-1">
                    <span
                      className="h-2.5 w-3.5 rounded-sm border-2"
                      style={{
                        borderColor: SEV_COLOR[s],
                        background: "#141d31",
                      }}
                    />
                    {SEVERITY_META[s].label}
                  </span>
                ),
              )}
            </div>
          </div>

          <div
            ref={containerRef}
            className="absolute inset-x-0 bottom-20 top-10"
          />
        </div>
        {/* Dock details so they never cover the selected graph neighborhood. */}
        {inspect && (
          <div
            className="absolute inset-y-0 right-0 z-20 w-80 max-w-[95%] overflow-y-auto border-l border-border bg-surface p-3.5 lg:static lg:flex-none"
            aria-label="Graph asset details"
          >
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-1.5 text-[10px] font-medium uppercase tracking-wider text-ink-faint">
                  <Swatch c={TYPE_DOT[inspect.type] ?? "#8696b0"} />
                  {inspect.kind === "cluster"
                    ? `${inspect.type} group`
                    : inspect.type}
                </div>
                <div className="mt-0.5 break-all font-mono text-[13px] text-ink">
                  {inspect.label}
                </div>
              </div>
              <button
                aria-label="Close graph details"
                onClick={() => {
                  setInspect(null);
                  pinnedRef.current = null;
                  cyRef.current?.nodes().removeClass("pinned");
                  cyRef.current?.elements().removeClass("lit dim");
                }}
                className="btn-ghost p-1"
              >
                <X size={14} />
              </button>
            </div>
            {inspect.severity && inspect.severity !== "none" && (
              <div className="mt-2">
                <span
                  className={cn(
                    "inline-flex rounded-full px-2 py-0.5 text-[11px]",
                    SEVERITY_META[inspect.severity].bg,
                    SEVERITY_META[inspect.severity].text,
                  )}
                >
                  {SEVERITY_META[inspect.severity].label} severity
                </span>
              </div>
            )}
            {inspect.kind === "cluster" && inspect.cluster ? (
              <>
                {!isOverview && (
                  <button
                    className="btn-outline mt-3 w-full"
                    onClick={() => {
                      setExpanded(
                        new Set([
                          ...expanded,
                          ...inspect.cluster!.members.map(
                            (member) => member.id,
                          ),
                        ]),
                      );
                      setFullMap(true);
                      setFocus("");
                      setInspect(null);
                    }}
                  >
                    Expand all {inspect.cluster.members.length} assets
                  </button>
                )}
                {isOverview && (
                  <p className="mt-3 text-xs text-ink-dim">
                    {TYPE_LABELS[inspect.type] || inspect.type} are grouped for
                    navigation. Each member keeps its original identity and
                    evidence. Choose one to explore its connections.
                  </p>
                )}
                <div className="mt-3 text-[11px] font-medium uppercase tracking-wider text-ink-faint">
                  {inspect.cluster.members.length}{" "}
                  {inspect.type === "url" ? "endpoints" : inspect.type}
                </div>
                <input
                  aria-label="Search category members"
                  className="my-2 w-full rounded border border-border bg-base p-2 text-xs"
                  placeholder="Find a member…"
                  value={memberQuery}
                  onChange={(e) => {
                    setMemberQuery(e.target.value);
                    setMemberPage(0);
                  }}
                />
                <div className="mt-1 space-y-0.5">
                  {inspect.cluster.members
                    .filter((m) =>
                      m.label.toLowerCase().includes(memberQuery.toLowerCase()),
                    )
                    .slice(memberPage * 30, (memberPage + 1) * 30)
                    .map((m) => (
                      <button
                        key={m.id}
                        onClick={() => focusNode(m.id)}
                        className="flex w-full items-center gap-1.5 rounded p-1 text-left text-[12px] hover:bg-white/5"
                        title={m.label}
                      >
                        {m.severity && m.severity !== "none" && (
                          <span
                            className="h-1.5 w-1.5 flex-none rounded-full"
                            style={{ background: SEV_COLOR[m.severity] }}
                          />
                        )}
                        <span className="break-all font-mono text-ink-dim">
                          {m.label}
                        </span>
                      </button>
                    ))}
                </div>
                <div className="mt-3 flex items-center justify-between text-xs">
                  <button
                    className="btn-ghost"
                    disabled={!memberPage}
                    onClick={() => setMemberPage(memberPage - 1)}
                  >
                    Previous
                  </button>
                  <span>
                    {memberPage + 1} /{" "}
                    {Math.max(
                      1,
                      Math.ceil(
                        inspect.cluster.members.filter((m) =>
                          m.label
                            .toLowerCase()
                            .includes(memberQuery.toLowerCase()),
                        ).length / 30,
                      ),
                    )}
                  </span>
                  <button
                    className="btn-ghost"
                    disabled={
                      (memberPage + 1) * 30 >=
                      inspect.cluster.members.filter((m) =>
                        m.label
                          .toLowerCase()
                          .includes(memberQuery.toLowerCase()),
                      ).length
                    }
                    onClick={() => setMemberPage(memberPage + 1)}
                  >
                    Next
                  </button>
                </div>
              </>
            ) : (
              <>
                <button
                  className="btn-outline mt-3 w-full"
                  onClick={() => focusNode(inspect.id)}
                >
                  Focus on this asset
                </button>
                <p className="mt-3 break-all text-xs text-ink-dim">
                  Asset evidence confidence:{" "}
                  {nodeIndex.get(inspect.id)?.confidence || "not recorded"}
                  <br />
                  Sources:{" "}
                  {nodeIndex.get(inspect.id)?.source_tools?.join(", ") ||
                    "not recorded"}
                </p>
                <div className="mt-4 border-y border-border py-3">
                  <h4 className="text-xs font-medium">
                    Associated security findings (
                    {nodeIndex.get(inspect.id)?.findings?.length || 0})
                  </h4>
                  <p className="my-2 text-[11px] text-ink-faint">
                    Explicit target / asset associations. Asset confidence does
                    not verify a vulnerability.
                  </p>
                  {nodeIndex.get(inspect.id)?.findings?.map((f) => (
                    <button
                      key={f.id}
                      className="mt-2 block w-full rounded border border-border p-2 text-left text-xs hover:bg-white/5"
                      onClick={() => setEvidence({ kind: "finding", id: f.id })}
                    >
                      <span className="block text-amber">
                        {f.severity} · {f.confidence}
                      </span>
                      {f.title}
                    </button>
                  ))}
                  {!nodeIndex.get(inspect.id)?.findings?.length && (
                    <p className="text-xs text-ink-dim">
                      No classified finding is associated with this asset. This
                      is not a clean bill of health.
                    </p>
                  )}
                </div>
                <button
                  className="btn-outline mt-3 w-full"
                  onClick={() => setEvidence({ kind: "asset", id: inspect.id })}
                >
                  Inspect complete stored asset
                </button>
                {!!nodeIndex.get(inspect.id)?.observation_ids?.length && (
                  <div className="mt-2 text-[10px] text-ink-faint">
                    Observations:{" "}
                    {nodeIndex.get(inspect.id)?.observation_ids?.map((id) => (
                      <button
                        key={id}
                        className="mr-2 break-all font-mono underline"
                        onClick={() => setEvidence({ kind: "observation", id })}
                      >
                        {id}
                      </button>
                    ))}
                  </div>
                )}
                <details className="mt-3">
                  <summary className="cursor-pointer text-xs text-ink-dim">
                    Full asset metadata
                  </summary>
                  <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-[11px]">
                    {JSON.stringify(
                      nodeIndex.get(inspect.id)?.metadata || {},
                      null,
                      2,
                    )}
                  </pre>
                </details>
                <div className="mt-3 text-[11px] font-medium uppercase tracking-wider text-ink-faint">
                  Connections ({inspect.neighbors?.length ?? 0})
                </div>
                <div className="mt-1 max-h-72 space-y-1 overflow-y-auto">
                  {inspect.neighbors?.map((nb, i) => (
                    <button
                      key={i}
                      onClick={() => focusNode(nb.id)}
                      className="flex w-full items-start gap-1.5 rounded p-1 text-left text-[12px] text-ink-dim hover:bg-white/5"
                    >
                      <span className="font-mono text-[10px] text-ink-faint">
                        {nb.dir === "out" ? "→" : "←"}
                      </span>
                      <span className="text-ink-faint">{nb.rel}</span>
                      <span className="break-all font-mono text-ink-dim">
                        {nb.label}
                      </span>
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        )}
        {edgeInspect && (
          <aside
            className="absolute inset-y-0 right-0 z-20 w-80 max-w-[95%] overflow-y-auto border-l border-border bg-surface p-4 lg:static lg:flex-none"
            aria-label="Relationship details"
          >
            <div className="flex items-center justify-between">
              <h3 className="font-medium">Recorded relationships</h3>
              <button
                className="btn-ghost"
                aria-label="Close relationship details"
                onClick={() => setEdgeInspect(null)}
              >
                <X size={14} />
              </button>
            </div>
            <p className="my-3 text-xs text-ink-dim">
              Arrows retain their stored direction. These are evidence
              relationships, not an attack path or proof of exploitability.
            </p>
            <p className="text-xs text-amber">
              {selectedEdges.length} stored relationships
            </p>
            <div className="my-3 flex flex-wrap gap-1">
              {relationCounts.map(([relation, count]) => (
                <button
                  key={relation}
                  className="rounded border border-border px-2 py-1 text-[11px] text-ink-dim"
                  onClick={() => {
                    setRelationshipQuery(relation);
                    setEdgePage(0);
                  }}
                >
                  {relation.replaceAll("_", " ")} · {count}
                </button>
              ))}
            </div>
            <input
              aria-label="Filter relationships"
              value={relationshipQuery}
              onChange={(e) => {
                setRelationshipQuery(e.target.value);
                setEdgePage(0);
              }}
              placeholder="Search relation or asset…"
              className="w-full rounded border border-border bg-base p-2 text-xs"
            />
            <p className="mt-2 text-xs text-ink-faint">
              {filteredEdges.length} matching relationships
            </p>
            {filteredEdges
              .slice(edgePage * 30, (edgePage + 1) * 30)
              .map((edge, index) => (
                <details
                  key={index}
                  className="border-b border-border py-3 text-xs"
                >
                  <summary className="cursor-pointer break-all">
                    <span className="font-mono">
                      {nodeIndex.get(edge.data.source)?.label}
                    </span>
                    <span className="my-1 block text-amber">
                      {edge.data.hypothesis ? "Hypothesis · " : ""}
                      {edge.data.label} →
                    </span>
                    <span className="font-mono">
                      {nodeIndex.get(edge.data.target)?.label}
                    </span>
                  </summary>
                  <button
                    className="btn-ghost mt-2"
                    onClick={() => focusNode(edge.data.source)}
                  >
                    Explore source
                  </button>
                  <button
                    className="btn-ghost"
                    onClick={() => focusNode(edge.data.target)}
                  >
                    Explore destination
                  </button>
                  {edge.data.observation_ids?.map((id) => (
                    <button
                      key={id}
                      className="mt-2 block break-all text-left underline"
                      onClick={() => setEvidence({ kind: "observation", id })}
                    >
                      Evidence: {id}
                    </button>
                  ))}
                  {!edge.data.observation_ids?.length && (
                    <p className="mt-2 text-ink-faint">
                      No observation reference was recorded for this
                      relationship.
                    </p>
                  )}
                </details>
              ))}
            <div className="mt-3 flex items-center justify-between text-xs">
              <button
                className="btn-ghost"
                disabled={!edgePage}
                onClick={() => setEdgePage(edgePage - 1)}
              >
                Previous
              </button>
              <span>
                {edgePage + 1} /{" "}
                {Math.max(1, Math.ceil(filteredEdges.length / 30))}
              </span>
              <button
                className="btn-ghost"
                disabled={(edgePage + 1) * 30 >= filteredEdges.length}
                onClick={() => setEdgePage(edgePage + 1)}
              >
                Next
              </button>
            </div>
          </aside>
        )}
        {evidence && (
          <RecordInspector
            engagementId={engagementId}
            records={[evidence]}
            title={evidence.id}
            onClose={() => setEvidence(null)}
          />
        )}
      </div>
    </div>
  );
}

function Swatch({ c }: { c: string }) {
  return (
    <span
      className="h-2 w-2 flex-none rounded-full"
      style={{ background: c }}
    />
  );
}
