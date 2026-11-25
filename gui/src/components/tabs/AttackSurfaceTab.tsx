"use client";

import { useState } from "react";
import { Radar, RefreshCw, ArrowUpRight, Globe, Server, Cpu, Layers, Mail, KeyRound, Network, type LucideIcon } from "lucide-react";
import { getReport } from "@/lib/api";
import type { ReportData } from "@/lib/types";
import { useResource } from "@/hooks/useResource";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { RecordInspector } from "@/components/ui/RecordInspector";
import type { RecordReference } from "@/lib/types";
import { Chip, Page, Card, StatTile } from "@/components/ui/primitives";
import { Loading, EmptyState, ErrorState } from "@/components/ui/States";

const SECTION_ICON: Record<string, LucideIcon> = {
  subdomains: Globe,
  hosts: Server,
  ports: Network,
  services: Cpu,
  tech: Layers,
  technologies: Layers,
  emails: Mail,
  identities: Mail,
  secrets: KeyRound,
};

type Item = ReportData["recon_appendix"][number]["items"][number];

const columns: Column<Item>[] = [
  {
    key: "value",
    header: "Asset",
    sortKey: (row) => row.value,
    className: "w-[45%]",
    cell: (row) => (
      <span className="break-all font-mono text-xs text-ink">{row.value}</span>
    ),
  },
  {
    key: "type",
    header: "Type",
    sortKey: (row) => row.type,
    cell: (row) => <Chip>{row.type.replaceAll("_", " ")}</Chip>,
  },
  {
    key: "detail",
    header: "Context",
    cell: (row) => (
      <span className="break-words text-xs">
        {row.detail || "No additional context recorded"}
      </span>
    ),
  },
  {
    key: "source",
    header: "Source",
    sortKey: (row) => row.source_tool,
    cell: (row) => (
      <span className="break-all text-xs text-ink-faint">
        {row.source_tool || "Engagement graph"}
      </span>
    ),
  },
];

export function AttackSurfaceTab({ engagementId }: { engagementId: string }) {
  // The inventory and report share one normalized projection, including legacy
  // assets. No per-tab interpretation of raw parser details or duplicate counts.
  const resource = useResource(
    (signal) => getReport(engagementId, signal),
    [engagementId],
  );
  const [selected, setSelected] = useState("");
  const [inspect, setInspect] = useState<Item | null>(null);
  if (resource.loading && !resource.loaded)
    return <Loading label="Building asset inventory…" />;
  if (resource.error)
    return <ErrorState message={resource.error} onRetry={resource.refetch} />;
  const sections = resource.data?.recon_appendix || [];
  const active =
    sections.find((section) => section.key === selected) || sections[0];
  const total = sections.reduce((sum, section) => sum + section.count, 0);
  const rowRecords = (item: Item): RecordReference[] =>
    item.record_refs || [
      ...(item.observation_id
        ? [{ kind: "observation" as const, id: item.observation_id }]
        : []),
      ...(item.finding_id
        ? [{ kind: "finding" as const, id: item.finding_id }]
        : []),
      ...(item.asset_id ? [{ kind: "asset" as const, id: item.asset_id }] : []),
    ];
  const detailColumns: Column<Item>[] = [
    ...columns,
    {
      key: "evidence",
      header: "Evidence",
      cell: (item) => (
        <button
          disabled={!rowRecords(item).length}
          onClick={() => setInspect(item)}
          className="btn-ghost text-xs"
        >
          Inspect ({rowRecords(item).length})
        </button>
      ),
    },
  ];
  if (!active)
    return (
      <EmptyState
        icon={Radar}
        title="No assets recorded"
        hint="Reconnaissance populates this inventory. Raw execution logs are kept separately."
      />
    );
  return (
    <Page
      eyebrow="Attack surface"
      title={`${total.toLocaleString()} assets mapped.`}
      subtitle={`${sections.length} categories discovered.`}
      description="Select a category to explore its evidence. Discovery records establish surface, not exploitability."
      actions={
        <button className="btn-outline" onClick={resource.refetch}>
          <RefreshCw size={14} /> Refresh
        </button>
      }
    >
      {resource.data?.data_limits?.possibly_partial && (
        <p className="rounded-lg border border-warn/30 bg-warn/[0.07] px-3 py-2 text-[12.5px] text-warn">
          Inventory assembly reached a record limit; use Evidence to search and page through the complete original store.
        </p>
      )}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        {sections.map((section) => (
          <StatTile
            key={section.key}
            icon={SECTION_ICON[section.key] ?? Network}
            tone={active.key === section.key ? "accent" : "neutral"}
            label={section.label}
            value={section.count}
            active={active.key === section.key}
            onClick={() => setSelected(section.key)}
          />
        ))}
      </div>
      <Card
        title={active.label}
        icon={SECTION_ICON[active.key] ?? Network}
        count={active.count.toLocaleString()}
        padded={false}
      >
        <div className="p-4">
          <DataTable
            key={active.key}
            rows={active.items}
            columns={detailColumns}
            getRowKey={(item, i) => `${item.type}:${item.value}:${i}`}
            initialSort={{ key: "value", dir: "asc" }}
            filter={(item, query) => `${item.value} ${item.detail} ${item.source_tool}`.toLowerCase().includes(query)}
            searchPlaceholder={`Search ${active.label.toLowerCase()}…`}
          />
          <p className="mt-4 flex items-center gap-1.5 text-[12px] text-ink-faint">
            <ArrowUpRight size={12} /> Discovery records establish surface, not exploitability. Review security conclusions in
            Findings.
          </p>
        </div>
      </Card>
      {inspect && (
        <RecordInspector
          engagementId={engagementId}
          records={rowRecords(inspect)}
          title={inspect.value}
          onClose={() => setInspect(null)}
        />
      )}
    </Page>
  );
}
