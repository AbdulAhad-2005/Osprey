/**
 * Attack-surface graph model.
 *
 * The raw `/visualization` graph is dominated by large leaf fans — e.g. 150+
 * `url` nodes all `hosted_on` one host, dozens of `technology` nodes, every
 * harvested `email`. Rendered one-node-per-fact with every label on, it is an
 * unreadable wall (what the old breadthfirst view showed). This module folds
 * those noisy degree-1 leaf sets into a single **cluster node** per
 * (parent, type) — "163 endpoints", "20 technologies" — whose members are
 * listed in the inspector on demand, keeping the canvas to the load-bearing
 * structure (domains → subdomains → hosts → ports/services) plus compact
 * cluster badges. Nothing is dropped; it is relocated from canvas to panel.
 */
import type { CytoGraph, Severity } from "./types";

/** Leaf types collapsed into per-parent cluster badges when numerous. */
const COLLAPSE_TYPES = new Set([
  "subdomain",
  "host",
  "ip",
  "url",
  "technology",
  "email",
  "phone",
  "port",
  "service",
]);
const COLLAPSE_MIN = 4;

/** Dagre's synchronous rank optimization can freeze a browser on large maps.
 * Change only the layout strategy, never the set of represented records. */
export function responsiveLayout(requested: string, nodeCount: number): string {
  return requested === "dagre" && nodeCount > 150 ? "grid" : requested;
}

const SEV_RANK: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
  none: 0,
};

export interface GNodeData {
  id: string;
  label: string;
  type: string;
  severity: Severity;
  /** connections after collapsing — drives node size */
  degree: number;
  /** cluster badge metadata */
  isCluster?: boolean;
  clusterType?: string;
  count?: number;
  /** a root domain / primary target — always labelled, drawn largest */
  primary?: boolean;
}
export interface GEdgeData {
  id: string;
  source: string;
  target: string;
  label: string;
  hypothesis?: boolean;
  /** Original edge indices, including parallel evidence-bearing edges. */
  records?: number[];
  count?: number;
}
export interface ClusterMember {
  id: string;
  label: string;
  type: string;
  severity: Severity;
}
export interface Cluster {
  id: string;
  parentId: string;
  type: string;
  edgeLabel: string;
  members: ClusterMember[];
  severity: Severity;
}
export interface ProcessedGraph {
  nodes: { data: GNodeData }[];
  edges: { data: GEdgeData }[];
  clusters: Map<string, Cluster>;
  stats: { total: number; shown: number; collapsed: number; clusters: number };
}

function plural(type: string, n: number): string {
  const label =
    type === "url" ? "endpoint" : type === "technology" ? "technology" : type;
  if (n === 1) return label;
  if (type === "technology") return "technologies";
  return label + "s";
}

function maxSev(items: { severity?: string }[]): Severity {
  let best: Severity = "none";
  for (const it of items) {
    if ((SEV_RANK[it.severity ?? "none"] ?? 0) > (SEV_RANK[best] ?? 0))
      best = (it.severity as Severity) ?? "none";
  }
  return best;
}

export function processGraph(
  graph: CytoGraph,
  primaryTarget?: string,
  options: { group?: boolean; expanded?: ReadonlySet<string> } = {},
): ProcessedGraph {
  const nodeById = new Map(graph.nodes.map((n) => [n.data.id, n.data]));
  const degree = new Map<string, number>();
  const incident = new Map<
    string,
    { edge: CytoGraph["edges"][number]; other: string }[]
  >();
  for (const e of graph.edges) {
    const { source, target } = e.data;
    if (!nodeById.has(source) || !nodeById.has(target)) continue;
    degree.set(source, (degree.get(source) ?? 0) + 1);
    degree.set(target, (degree.get(target) ?? 0) + 1);
    (incident.get(source) ?? incident.set(source, []).get(source)!).push({
      edge: e,
      other: target,
    });
    (incident.get(target) ?? incident.set(target, []).get(target)!).push({
      edge: e,
      other: source,
    });
  }

  // Group collapsible degree-1 leaves by (parent, type, edgeLabel).
  const groups = new Map<
    string,
    { parentId: string; type: string; edgeLabel: string; members: string[] }
  >();
  const grouped = new Set<string>();
  for (const [id, data] of nodeById) {
    if (options.group === false || options.expanded?.has(id)) continue;
    if (primaryTarget && data.label.toLowerCase() === primaryTarget.toLowerCase()) continue;
    if (!COLLAPSE_TYPES.has(data.type)) continue;
    if ((SEV_RANK[data.severity || "none"] || 0) >= 3) continue;
    const neighbors = [
      ...new Set(
        (incident.get(id) || []).map(
          (item) =>
            `${item.edge.data.source === id ? "out" : "in"}:${item.other}:${item.edge.data.label}:${!!item.edge.data.hypothesis}`,
        ),
      ),
    ].sort();
    if (neighbors.length > 3) continue;
    const inc = incident.get(id)?.[0];
    const key = `${data.type}::${neighbors.join("|") || "unlinked"}`;
    const g = groups.get(key) ?? {
      parentId: inc?.other || "",
      type: data.type,
      edgeLabel: inc?.edge.data.label || "unlinked",
      members: [],
    };
    g.members.push(id);
    groups.set(key, g);
  }

  const clusters = new Map<string, Cluster>();
  const metaNodes: { data: GNodeData }[] = [];
  let collapsedCount = 0;
  for (const [key, g] of groups) {
    if (g.members.length < COLLAPSE_MIN) continue;
    const members: ClusterMember[] = g.members.map((mid) => {
      grouped.add(mid);
      const d = nodeById.get(mid)!;
      return {
        id: d.id,
        label: d.label,
        type: d.type,
        severity: (d.severity as Severity) ?? "none",
      };
    });
    const cid = `cluster::${key}`;
    const sev = maxSev(members);
    clusters.set(cid, {
      id: cid,
      parentId: g.parentId,
      type: g.type,
      edgeLabel: g.edgeLabel,
      members,
      severity: sev,
    });
    metaNodes.push({
      data: {
        id: cid,
        label: `${g.members.length} ${plural(g.type, g.members.length)}`,
        type: "cluster",
        clusterType: g.type,
        severity: sev,
        degree: 1,
        isCluster: true,
        count: g.members.length,
      },
    });
    collapsedCount += g.members.length;
  }

  // Primary targets: domains that are not the target of a subdomain_of/hosted_on
  // edge (i.e. roots). Fallback: all domains.
  const childDomains = new Set(
    graph.edges
      .filter((e) => e.data.label === "subdomain_of")
      .map((e) => e.data.source),
  );

  const nodes: { data: GNodeData }[] = [];
  for (const n of graph.nodes) {
    if (grouped.has(n.data.id)) continue;
    const d = n.data;
    const deg = degree.get(d.id) ?? 0;
    nodes.push({
      data: {
        id: d.id,
        label: d.label,
        type: d.type,
        severity: (d.severity as Severity) ?? "none",
        degree: deg,
        primary: primaryTarget
          ? d.label.toLowerCase() === primaryTarget.toLowerCase()
          : d.type === "domain" && !childDomains.has(d.id),
      },
    });
  }
  nodes.push(...metaNodes);

  const edges: { data: GEdgeData }[] = [];
  const groupedInto = new Map<string, string>();
  for (const cluster of clusters.values())
    for (const member of cluster.members)
      groupedInto.set(member.id, cluster.id);
  const edgeByKey = new Map<string, GEdgeData>();
  for (const [index, e] of graph.edges.entries()) {
    const source = groupedInto.get(e.data.source) || e.data.source;
    const target = groupedInto.get(e.data.target) || e.data.target;
    if (
      !nodeById.has(e.data.source) ||
      !nodeById.has(e.data.target) ||
      (source === target && e.data.source !== e.data.target)
    )
      continue;
    const key = JSON.stringify([
      source,
      e.data.label,
      target,
      !!e.data.hypothesis,
    ]);
    if (edgeByKey.has(key)) {
      edgeByKey.get(key)!.records!.push(index);
      continue;
    }
    edges.push({
      data: {
        id: key,
        source,
        target,
        label: e.data.label,
        hypothesis: e.data.hypothesis,
        records: [index],
      },
    });
    edgeByKey.set(key, edges[edges.length - 1]!.data);
  }

  return {
    nodes,
    edges,
    clusters,
    stats: {
      total: graph.nodes.length,
      shown: nodes.length,
      collapsed: collapsedCount,
      clusters: clusters.size,
    },
  };
}

/** A direct (optionally two-hop) neighborhood, selected from the full raw graph so even a
 * grouped member remains individually searchable and inspectable. */
export function graphNeighborhood(
  graph: CytoGraph,
  id: string,
  hops = 1,
): CytoGraph {
  const visible = new Set([id]);
  const kinds = new Map(
    graph.nodes.map((node) => [node.data.id, node.data.type]),
  );
  for (let hop = 0; hop < hops; hop++) {
    const prior = new Set(visible);
    for (const edge of graph.edges) {
      if (
        prior.has(edge.data.source) &&
        (edge.data.source === id || kinds.get(edge.data.source) !== "domain")
      )
        visible.add(edge.data.target);
      if (
        prior.has(edge.data.target) &&
        (edge.data.target === id || kinds.get(edge.data.target) !== "domain")
      )
        visible.add(edge.data.source);
    }
  }
  return {
    nodes: graph.nodes.filter((node) => visible.has(node.data.id)),
    edges: graph.edges.filter(
      (edge) => visible.has(edge.data.source) && visible.has(edge.data.target),
    ),
  };
}
