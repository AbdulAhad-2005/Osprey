import { describe, expect, it } from "vitest";
import {
  graphNeighborhood,
  processGraph,
  responsiveLayout,
} from "./graphModel";
import type { CytoGraph } from "./types";

function fixture(): CytoGraph {
  return {
    nodes: [
      {
        data: {
          id: "root",
          label: "example.test",
          type: "domain",
          severity: "none",
        },
      },
      ...Array.from({ length: 100 }, (_, i) => ({
        data: {
          id: `h${i}`,
          label: `h${i}.example.test`,
          type: "host",
          severity: i === 99 ? "high" : "none",
        },
      })),
    ],
    edges: Array.from({ length: 100 }, (_, i) => ({
      data: {
        id: `e${i}`,
        source: `h${i}`,
        target: "root",
        label: "subdomain_of",
      },
    })),
  };
}

describe("graph presentation", () => {
  it("uses a fast layout for large maps without changing their records", () => {
    expect(responsiveLayout("dagre", 1339)).toBe("grid");
    expect(responsiveLayout("dagre", 267)).toBe("grid");
    expect(responsiveLayout("dagre", 40)).toBe("dagre");
    expect(responsiveLayout("concentric", 1339)).toBe("concentric");
  });
  it("can show every individual asset without grouping", () => {
    const graph = processGraph(fixture(), undefined, { group: false });
    expect(graph.nodes).toHaveLength(101);
    expect(graph.edges).toHaveLength(100);
    expect(graph.clusters.size).toBe(0);
  });
  it("keeps a chosen or expanded member individually visible", () => {
    const graph = processGraph(fixture(), undefined, {
      expanded: new Set(["h1"]),
    });
    expect(graph.nodes.some((node) => node.data.id === "h1")).toBe(true);
    expect(
      [...graph.clusters.values()]
        .flatMap((cluster) => cluster.members)
        .some((member) => member.id === "h1"),
    ).toBe(false);
    const represented =
      graph.nodes.filter((node) => !node.data.isCluster).length +
      [...graph.clusters.values()].reduce(
        (n, cluster) => n + cluster.members.length,
        0,
      );
    expect(represented).toBe(101);
  });
  it("groups equivalent neighbors without losing members or risk", () => {
    const graph = processGraph(fixture());
    expect(graph.nodes).toHaveLength(3);
    expect([...graph.clusters.values()][0]?.members).toHaveLength(99);
    expect(graph.nodes.find((n) => n.data.id === "h99")?.data.severity).toBe(
      "high",
    );
    expect(graph.edges).toHaveLength(2);
    expect(
      graph.edges.every(
        (e) =>
          graph.nodes.some((n) => n.data.id === e.data.source) &&
          graph.nodes.some((n) => n.data.id === e.data.target),
      ),
    ).toBe(true);
  });
  it("does not expand all siblings through a domain hub", () => {
    const graph = graphNeighborhood(fixture(), "h1");
    expect(graph.nodes.map((n) => n.data.id).sort()).toEqual(["h1", "root"]);
  });
});
