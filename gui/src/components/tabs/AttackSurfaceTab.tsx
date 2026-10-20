"use client";

import { Network, Server, Globe, Users, KeyRound, ShieldAlert, Radar, type LucideIcon } from "lucide-react";
import { listFindings, listObservations } from "@/lib/api";
import { useResource } from "@/hooks/useResource";
import {
  SURFACE_BUCKETS,
  STAT_CATEGORIES,
  bucketObservations,
  countByTypes,
  obsDetail,
  obsValue,
  severityRollup,
  SEVERITY_ORDER,
} from "@/lib/surface";
import type { Observation, Severity } from "@/lib/types";
import { SEVERITY_META } from "@/lib/format";
import { cn } from "@/lib/cn";
import { Card, SectionHeader, StatTile, Chip } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/ui/DataTable";
import { ConfidenceDot } from "@/components/ui/SeverityPill";
import { Loading, EmptyState, ErrorState } from "@/components/ui/States";

const BUCKET_ICON: Record<string, LucideIcon> = {
  infra: Network,
  services: Server,
  web: Globe,
  identity: Users,
  secrets: KeyRound,
};

export function AttackSurfaceTab({ engagementId }: { engagementId: string }) {
  const obs = useResource((s) => listObservations(engagementId, s), [engagementId]);
  const fnd = useResource((s) => listFindings(engagementId, s), [engagementId]);

  if (obs.loading && !obs.loaded) return <Loading label="Loading attack surface…" />;
  if (obs.error) return <ErrorState message={obs.error} onRetry={obs.refetch} />;

  const observations = obs.data ?? [];
  const findings = fnd.data ?? [];
  const roll = severityRollup(findings);
  const vulnCount = findings.filter((f) => f.claim_severity && f.claim_severity !== "none").length;

  if (observations.length === 0 && findings.length === 0) {
    return (
      <EmptyState
        icon={Radar}
        title="No attack surface mapped yet"
        hint="Run recon from the Chat tab — subdomains, hosts, ports, services and OSINT will populate here as Osprey discovers them."
      />
    );
  }

  return (
    <div className="mx-auto max-w-6xl space-y-5 px-5 py-5">
      {/* Stat tiles */}
      <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 lg:grid-cols-6">
        {STAT_CATEGORIES.map((c) => {
          const n = countByTypes(observations, c.types);
          return <StatTile key={c.key} label={c.label} value={n} accent={n ? "text-ink" : "text-ink-faint"} />;
        })}
        <StatTile
          label="Vulnerabilities"
          value={vulnCount}
          icon={ShieldAlert}
          accent={vulnCount ? "text-sev-high" : "text-ink-faint"}
        />
      </div>

      {/* Severity rollup */}
      {vulnCount > 0 && <SeverityBar roll={roll} total={vulnCount} />}

      {/* Buckets */}
      {SURFACE_BUCKETS.map((bucket) => {
        const rows = bucketObservations(observations, bucket.types);
        if (rows.length === 0) return null;
        const Icon = BUCKET_ICON[bucket.key] ?? Network;
        return (
          <Card key={bucket.key} className="p-4">
            <SectionHeader title={bucket.label} count={rows.length} icon={Icon} accent="text-amber" />
            <ObservationTable rows={rows} bucket={bucket.key} />
          </Card>
        );
      })}
    </div>
  );
}

function SeverityBar({ roll, total }: { roll: Record<Severity, number>; total: number }) {
  const shown = SEVERITY_ORDER.filter((s) => s !== "none" && roll[s] > 0);
  return (
    <Card className="p-4">
      <SectionHeader title="Findings by severity" count={total} icon={ShieldAlert} accent="text-sev-high" />
      <div className="flex h-2.5 w-full overflow-hidden rounded-full bg-surface-2">
        {shown.map((s) => (
          <div
            key={s}
            className={SEVERITY_META[s].dot}
            style={{ width: `${(roll[s] / total) * 100}%` }}
            title={`${SEVERITY_META[s].label}: ${roll[s]}`}
          />
        ))}
      </div>
      <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1.5">
        {shown.map((s) => (
          <span key={s} className="flex items-center gap-1.5 text-[12px] text-ink-dim">
            <span className={cn("h-2 w-2 rounded-full", SEVERITY_META[s].dot)} />
            {SEVERITY_META[s].label}
            <span className="font-mono text-ink">{roll[s]}</span>
          </span>
        ))}
      </div>
    </Card>
  );
}

function ObservationTable({ rows, bucket }: { rows: Observation[]; bucket: string }) {
  const columns: Column<Observation>[] = [
    {
      key: "type",
      header: "Type",
      sortKey: (o) => o.type,
      cell: (o) => <Chip>{o.type.replace(/_/g, " ")}</Chip>,
    },
    {
      key: "value",
      header: "Value",
      sortKey: (o) => obsValue(o),
      className: "w-[42%]",
      cell: (o) => (
        <span
          className={cn(
            "break-all font-mono text-[12.5px]",
            bucket === "secrets" ? "text-amber-soft" : "text-ink",
          )}
        >
          {obsValue(o)}
        </span>
      ),
    },
    {
      key: "detail",
      header: "Detail",
      cell: (o) => <span className="text-[12px] text-ink-dim">{obsDetail(o) || "—"}</span>,
    },
    {
      key: "source",
      header: "Source",
      sortKey: (o) => o.source_tool,
      cell: (o) => (o.source_tool ? <Chip className="text-ink-faint">{o.source_tool}</Chip> : <span className="text-ink-faint">—</span>),
    },
    {
      key: "conf",
      header: "Confidence",
      cell: (o) => <ConfidenceDot confidence={o.confidence} />,
    },
    {
      key: "count",
      header: "Seen",
      align: "right",
      sortKey: (o) => o.occurrence_count ?? 1,
      cell: (o) => <span className="font-mono text-[12px] text-ink-dim">{o.occurrence_count ?? 1}×</span>,
    },
  ];
  return (
    <DataTable
      rows={rows}
      columns={columns}
      getRowKey={(o) => o.id}
      initialSort={{ key: "type", dir: "asc" }}
      filter={(o, q) =>
        (obsValue(o) + " " + obsDetail(o) + " " + o.type + " " + o.source_tool).toLowerCase().includes(q)
      }
      searchPlaceholder="Filter…"
      dense
    />
  );
}
