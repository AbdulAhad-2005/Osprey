import type { CytoGraph } from "./types";
import type {
  Cluster,
  GEdgeData,
  GNodeData,
  ProcessedGraph,
} from "./graphModel";

export const TYPE_LABELS: Record<string, string> = {
  domain: "Domains",
  subdomain: "Subdomains",
  host: "Hosts",
  ip: "IP addresses",
  port: "Ports",
  service: "Services",
  url: "URLs",
  technology: "Technologies",
  email: "Email addresses",
  credential: "Credentials",
  secret: "Secrets",
};

/** A lossless category projection, not a ranked sample. Every loaded asset belongs
 * to exactly one category; every valid relationship belongs to one counted edge.
 * Categories are navigation aids, not claims that their members are equivalent. */
export function engagementOverview(graph: CytoGraph): ProcessedGraph {
  const clusters = new Map<string, Cluster>();
  const types = new Map<string, string>();
  const rank: Record<string, number> = {
    none: 0,
    info: 1,
    low: 2,
    medium: 3,
    high: 4,
    critical: 5,
  };
  for (const { data } of graph.nodes) {
    const id = `category::${data.type}`;
    types.set(data.id, id);
    const cluster = clusters.get(id) || {
      id,
      parentId: "",
      type: data.type,
      edgeLabel: "",
      members: [],
      severity: "none",
    };
    cluster.members.push(data);
    if ((rank[data.severity] || 0) > (rank[cluster.severity] || 0))
      cluster.severity = data.severity;
    clusters.set(id, cluster);
  }
  const nodes: { data: GNodeData }[] = [...clusters.values()].map((c) => ({
    data: {
      id: c.id,
      type: "cluster",
      clusterType: c.type,
      isCluster: true,
      label: `${TYPE_LABELS[c.type] || c.type}\n${c.members.length.toLocaleString()} ${c.members.length === 1 ? "record" : "records"}`,
      count: c.members.length,
      severity: c.severity,
      degree: 0,
    },
  }));
  const edges = new Map<string, GEdgeData>();
  graph.edges.forEach(({ data }, index) => {
    const source = types.get(data.source),
      target = types.get(data.target);
    if (!source || !target) return;
    const id = JSON.stringify([source, target, !!data.hypothesis]);
    const edge = edges.get(id) || {
      id,
      source,
      target,
      label: "",
      hypothesis: data.hypothesis,
      records: [],
      count: 0,
    };
    edge.count!++;
    edge.records!.push(index);
    edge.label = `${edge.count} ${edge.count === 1 ? "link" : "links"}`;
    edges.set(id, edge);
  });
  return {
    nodes,
    edges: [...edges.values()].map((data) => ({ data })),
    clusters,
    stats: {
      total: graph.nodes.length,
      shown: nodes.length,
      collapsed: graph.nodes.length,
      clusters: clusters.size,
    },
  };
}

/** Deterministic, cheap overview layout. Stable category positions preserve the
 * operator's bearings when fresh evidence arrives. Unknown categories stay visible. */
export function overviewPositions(nodes: { data: GNodeData }[]) {
  const slots: Record<string, [number, number]> = {
    domain: [0, 0],
    subdomain: [0, 230],
    host: [310, 0],
    url: [310, 230],
    ip: [620, 0],
    technology: [620, 230],
    port: [930, 0],
    service: [930, 230],
  };
  let extra = 0;
  return Object.fromEntries(
    nodes.map(({ data }) => {
      const slot = slots[data.clusterType || ""] || [
        (extra % 4) * 310,
        460 + Math.floor(extra++ / 4) * 230,
      ];
      return [data.id, { x: slot[0], y: slot[1] }];
    }),
  );
}

/** A balanced local view reserves a readable card for each neighbor instead of
 * stretching a one-hop star into a very tall hierarchy. Directions stay on edges. */
export function neighborhoodPositions(
  nodes: { data: GNodeData }[],
  focus: string,
) {
  const neighbors = nodes
    .filter((n) => n.data.id !== focus)
    .sort(
      (a, b) =>
        a.data.type.localeCompare(b.data.type) ||
        a.data.label.localeCompare(b.data.label),
    );
  const positions: Record<string, { x: number; y: number }> = {
    [focus]: { x: 0, y: 0 },
  };
  // A long two-column star forces fit-to-view to shrink every label. Spread
  // larger neighborhoods across four columns while keeping the target central.
  const columns = neighbors.length > 12 ? [-500, -250, 250, 500] : [-300, 300];
  neighbors.forEach((node, index) => {
    const column = index % columns.length,
      count = Math.ceil((neighbors.length - column) / columns.length);
    positions[node.data.id] = {
      x: columns[column]!,
      y: (Math.floor(index / columns.length) - (count - 1) / 2) * 92,
    };
  });
  return positions;
}
