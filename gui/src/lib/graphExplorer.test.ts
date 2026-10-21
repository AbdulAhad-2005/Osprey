import { expect, it } from "vitest";
import { engagementOverview, neighborhoodPositions, overviewPositions } from "./graphExplorer";
import { graphNeighborhood, processGraph } from "./graphModel";
import type { CytoGraph } from "./types";

const graph: CytoGraph = {
  nodes: ["domain", "host", "host", "url", "unknown"].map((type, i) => ({
    data: { id: String(i), label: `asset${i}`, type, severity: "none" },
  })),
  edges: [
    {
      data: {
        source: "1",
        target: "0",
        label: "subdomain_of",
        hypothesis: false,
        observation_ids: ["a"],
      },
    },
    {
      data: {
        source: "1",
        target: "0",
        label: "subdomain_of",
        hypothesis: false,
        observation_ids: ["b"],
      },
    },
    {
      data: {
        source: "1",
        target: "0",
        label: "subdomain_of",
        hypothesis: true,
      },
    },
    {
      data: { source: "2", target: "1", label: "co_hosts", hypothesis: false },
    },
    {
      data: { source: "3", target: "2", label: "hosted_on", hypothesis: false },
    },
  ],
};

it("retains explicit self-links in the detailed topology", () => {
  const self: CytoGraph = {nodes: graph.nodes, edges:[{data:{source:"1",target:"1",label:"recorded_link",hypothesis:false}}]};
  expect(processGraph(self,undefined,{group:false}).edges).toHaveLength(1);
});

it("accounts for every asset and every edge including same-category links", () => {
  const overview = engagementOverview(graph);
  expect(
    [...overview.clusters.values()]
      .flatMap((c) => c.members.map((m) => m.id))
      .sort(),
  ).toEqual(["0", "1", "2", "3", "4"]);
  expect(overview.edges.flatMap((e) => e.data.records!).sort()).toEqual([
    0, 1, 2, 3, 4,
  ]);
  expect(overview.edges.some((e) => e.data.source === e.data.target)).toBe(
    true,
  );
  expect(Object.keys(overviewPositions(overview.nodes))).toHaveLength(4);
});

it("retains parallel provenance and does not merge hypotheses into recorded edges", () => {
  const result = processGraph(graph, undefined, { group: false });
  expect(
    result.edges.filter((e) => e.data.source === "1" && e.data.target === "0"),
  ).toHaveLength(2);
  expect(
    result.edges.find((e) => e.data.source === "1" && !e.data.hypothesis)?.data
      .records,
  ).toEqual([0, 1]);
  expect(graph.edges[0]?.data.source).toBe("1");
});

it("defaults to direct neighbors and expands two hops only on request", () => {
  expect(graphNeighborhood(graph, "3").nodes.map((n) => n.data.id)).toEqual([
    "2",
    "3",
  ]);
  expect(graphNeighborhood(graph, "3", 2).nodes.map((n) => n.data.id)).toEqual([
    "1",
    "2",
    "3",
  ]);
});

it("keeps overview partition and positions stable for large engagements", () => {
  const large: CytoGraph = {
    nodes: Array.from({ length: 5000 }, (_, i) => ({
      data: {
        id: String(i),
        label: `https://example.test/${i}`,
        type: "url",
        severity: "none",
      },
    })),
    edges: [],
  };
  const overview = engagementOverview(large);
  expect(overview.nodes[0]?.data.count).toBe(5000);
  expect(overview.clusters.get("category::url")?.members).toHaveLength(5000);
  expect(overviewPositions(overview.nodes)["category::url"]).toEqual({
    x: 310,
    y: 230,
  });
});

it("balances a focused neighborhood without overlaps or input-order dependence", () => {
  const nodes = processGraph(graph, undefined, { group: false }).nodes;
  const positions = neighborhoodPositions(nodes, "0");
  expect(positions["0"]).toEqual({ x: 0, y: 0 });
  expect(Object.keys(positions)).toHaveLength(graph.nodes.length);
  expect(new Set(Object.values(positions).map((p) => `${p.x},${p.y}`)).size)
    .toBe(graph.nodes.length);
  expect(neighborhoodPositions([...nodes].reverse(), "0")).toEqual(positions);
  expect(graph.nodes.map((n) => n.data.id)).toEqual(["0", "1", "2", "3", "4"]);
  const larger = Array.from({ length: 23 }, (_, i) => ({
    data: { id: String(i), label: `host${i}`, type: "host", severity: "none" as const, degree: 1 },
  }));
  const largerPositions = Object.values(neighborhoodPositions(larger, "0"));
  expect(Math.max(...largerPositions.map((p) => p.y)) - Math.min(...largerPositions.map((p) => p.y)))
    .toBeLessThanOrEqual(460);
});
