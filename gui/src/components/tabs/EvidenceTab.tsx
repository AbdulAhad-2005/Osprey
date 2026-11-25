"use client";

import { useState } from "react";
import { RefreshCw, Search, ChevronRight } from "lucide-react";
import { browseEvidence } from "@/lib/api";
import { useResource } from "@/hooks/useResource";
import { RecordInspector } from "@/components/ui/RecordInspector";
import { Loading, ErrorState } from "@/components/ui/States";
import { Page, Card, Chip, Segmented } from "@/components/ui/primitives";
import type { RecordReference } from "@/lib/types";

export function EvidenceTab({ engagementId }: { engagementId: string }) {
  const [kind, setKind] = useState<"observation" | "finding">("observation");
  const [page, setPage] = useState(0);
  const [query, setQuery] = useState("");
  const [draft, setDraft] = useState("");
  const [inspect, setInspect] = useState<RecordReference | null>(null);
  const resource = useResource(
    (signal) => browseEvidence(engagementId, kind, page, query, signal),
    [engagementId, kind, page, query],
  );
  const rows = resource.data || [];
  return (
    <Page
      eyebrow="Evidence explorer"
      title="Every stored record."
      subtitle="Nothing filtered out."
      description="Browse observed facts, scanner signals, and every stored finding row — including legacy discoveries and execution notes. These are not all validated vulnerabilities. Open a record for full details, evidence, timestamps, and identifiers."
      actions={
        <button className="btn-outline" onClick={resource.refetch}>
          <RefreshCw size={14} /> Refresh
        </button>
      }
    >
      <form
        className="flex flex-wrap items-center gap-3"
        onSubmit={(event) => {
          event.preventDefault();
          setPage(0);
          setQuery(draft.trim());
        }}
      >
        <Segmented
          label="Evidence collection"
          value={kind}
          onChange={(v) => {
            setKind(v);
            setPage(0);
          }}
          options={[
            { value: "observation", label: "Observations & signals" },
            { value: "finding", label: "All finding rows" },
          ]}
        />
        <label className="flex min-w-60 flex-1 items-center gap-2 rounded-lg border border-border bg-surface px-3 shadow-card focus-within:border-accent/60 focus-within:shadow-focus">
          <Search size={15} className="text-ink-faint" />
          <input
            aria-label="Search original records"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="Search target, source, ID, or evidence…"
            className="w-full bg-transparent py-2 text-[13px] outline-none placeholder:text-ink-faint"
          />
        </label>
        <button className="btn-primary" type="submit">
          Search
        </button>
      </form>
      {resource.loading ? (
        <Loading label="Loading evidence page…" />
      ) : resource.error ? (
        <ErrorState message={resource.error} onRetry={resource.refetch} />
      ) : rows.length === 0 ? (
        <Card>
          <p className="py-6 text-center text-[13px] text-ink-dim">
            No records on this page. Try a different collection or search.
          </p>
        </Card>
      ) : (
        <Card padded={false}>
          <ul className="divide-y divide-border">
            {rows.map((row) => (
              <li key={String(row.id)}>
                <button
                  onClick={() => setInspect({ kind, id: String(row.id) })}
                  className="group flex w-full items-center gap-4 px-4 py-3 text-left transition-colors hover:bg-accent/[0.05]"
                >
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <Chip>{String(row.type || row.finding_type || "record").replace(/_/g, " ")}</Chip>
                      <span className="text-[11.5px] text-ink-faint">
                        {String(row.confidence || "confidence not recorded")} · {String(row.source_tool || "source not recorded")}
                      </span>
                    </div>
                    <p className="mt-1.5 break-all text-[13.5px] font-medium text-ink">
                      {String(row.title || row.target || row.id)}
                    </p>
                    <p className="mt-0.5 break-all font-mono text-[11.5px] text-ink-faint">
                      {String(row.id)}
                      {row.target ? ` · ${String(row.target)}` : ""}
                    </p>
                  </div>
                  <ChevronRight size={16} className="flex-none text-ink-faint transition-transform group-hover:translate-x-0.5" />
                </button>
              </li>
            ))}
          </ul>
        </Card>
      )}
      <div className="flex items-center justify-end gap-3 text-xs">
        <span className="mr-auto text-ink-faint">40 records per page · searches run against the engagement store</span>
        <button className="btn-outline" disabled={!page || resource.loading} onClick={() => setPage(page - 1)}>
          Previous
        </button>
        <span className="text-ink-dim">Page {page + 1}</span>
        <button className="btn-outline" disabled={rows.length < 40 || resource.loading} onClick={() => setPage(page + 1)}>
          Next
        </button>
      </div>
      {inspect && (
        <RecordInspector engagementId={engagementId} records={[inspect]} title={inspect.id} onClose={() => setInspect(null)} />
      )}
    </Page>
  );
}
