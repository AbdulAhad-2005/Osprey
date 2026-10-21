"use client";

import { useState } from "react";
import { Radar, RefreshCw, ArrowUpRight } from "lucide-react";
import { getReport } from "@/lib/api";
import type { ReportData } from "@/lib/types";
import { useResource } from "@/hooks/useResource";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { RecordInspector } from "@/components/ui/RecordInspector";
import type { RecordReference } from "@/lib/types";
import { Chip } from "@/components/ui/primitives";
import { Loading, EmptyState, ErrorState } from "@/components/ui/States";
import { cn } from "@/lib/cn";

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
    <div className="mx-auto max-w-7xl p-5 md:p-7">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-[11px] uppercase tracking-[.18em] text-amber">
            Asset intelligence
          </p>
          <h2 className="mt-1 font-serif text-2xl text-ink">
            Attack surface inventory
          </h2>
          <p className="mt-2 text-sm text-ink-dim">
            {total.toLocaleString()} recorded entries across {sections.length}{" "}
            categories. Select a category to explore its evidence.
          </p>
          {resource.data?.data_limits?.possibly_partial && (
            <p className="mt-2 text-xs text-amber-soft">
              Inventory assembly reached a record limit; use Evidence to search
              and page through the complete original store.
            </p>
          )}
        </div>
        <button className="btn-outline" onClick={resource.refetch}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>
      <div className="grid items-start gap-5 lg:grid-cols-[220px_minmax(0,1fr)]">
        <nav
          aria-label="Asset categories"
          className="grid grid-cols-2 gap-2 lg:grid-cols-1"
        >
          {sections.map((section) => (
            <button
              key={section.key}
              onClick={() => setSelected(section.key)}
              aria-pressed={active.key === section.key}
              className={cn(
                "flex items-center justify-between rounded-xl border px-4 py-3 text-left text-sm",
                active.key === section.key
                  ? "border-amber/40 bg-amber/10 text-amber-soft"
                  : "border-border bg-surface text-ink-dim hover:text-ink",
              )}
            >
              <span>{section.label}</span>
              <span className="ml-3 font-mono text-xs">
                {section.count.toLocaleString()}
              </span>
            </button>
          ))}
        </nav>
        <section className="min-w-0 rounded-2xl border border-border bg-surface/50 p-4">
          <div className="mb-4 flex items-center gap-2">
            <Radar size={16} className="text-signal" />
            <h3 className="text-sm font-semibold">{active.label}</h3>
            <span className="ml-auto text-xs text-ink-faint">
              {active.count.toLocaleString()} assets
            </span>
          </div>
          <DataTable
            key={active.key}
            rows={active.items}
            columns={detailColumns}
            getRowKey={(item, i) => `${item.type}:${item.value}:${i}`}
            initialSort={{ key: "value", dir: "asc" }}
            filter={(item, query) =>
              `${item.value} ${item.detail} ${item.source_tool}`
                .toLowerCase()
                .includes(query)
            }
            searchPlaceholder={`Search ${active.label.toLowerCase()}…`}
          />
          <p className="mt-4 flex items-center gap-1 text-xs text-ink-faint">
            <ArrowUpRight size={12} /> Discovery records establish surface, not
            exploitability. Review security conclusions in Findings.
          </p>
        </section>
      </div>
      {inspect && (
        <RecordInspector
          engagementId={engagementId}
          records={rowRecords(inspect)}
          title={inspect.value}
          onClose={() => setInspect(null)}
        />
      )}
    </div>
  );
}
