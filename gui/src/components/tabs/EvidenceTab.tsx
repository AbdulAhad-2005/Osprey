"use client";

import { useState } from "react";
import { RefreshCw, Search } from "lucide-react";
import { browseEvidence } from "@/lib/api";
import { useResource } from "@/hooks/useResource";
import { RecordInspector } from "@/components/ui/RecordInspector";
import { Loading, ErrorState } from "@/components/ui/States";
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
    <div className="mx-auto max-w-6xl p-5 md:p-7">
      <div className="mb-5 flex items-start justify-between gap-3">
        <div>
          <p className="text-xs uppercase tracking-widest text-amber">
            Evidence explorer
          </p>
          <h2 className="mt-1 font-serif text-2xl">
            Original records, without presentation filters
          </h2>
          <p className="mt-2 max-w-3xl text-sm text-ink-dim">
            Browse observed facts, scanner signals, and every stored finding
            row—including legacy discoveries and execution notes. These are not
            all validated vulnerabilities. Open a record for full details,
            evidence, timestamps, and identifiers.
          </p>
        </div>
        <button className="btn-outline" onClick={resource.refetch}>
          <RefreshCw size={14} />
          Refresh
        </button>
      </div>
      <form
        className="mb-5 flex flex-wrap gap-2"
        onSubmit={(event) => {
          event.preventDefault();
          setPage(0);
          setQuery(draft.trim());
        }}
      >
        <select
          aria-label="Evidence collection"
          value={kind}
          onChange={(e) => {
            setKind(e.target.value as typeof kind);
            setPage(0);
          }}
          className="rounded-lg border border-border bg-surface px-3 py-2 text-sm"
        >
          <option value="observation">Observations & scanner signals</option>
          <option value="finding">All stored finding rows</option>
        </select>
        <input
          aria-label="Search original records"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Search target, source, ID, or evidence…"
          className="min-w-48 flex-1 rounded-lg border border-border bg-surface px-3 py-2 text-sm"
        />
        <button className="btn-outline" type="submit">
          <Search size={14} /> Search
        </button>
      </form>
      {resource.loading ? (
        <Loading label="Loading evidence page…" />
      ) : resource.error ? (
        <ErrorState message={resource.error} onRetry={resource.refetch} />
      ) : (
        <div className="space-y-2">
          {rows.length === 0 ? (
            <p className="rounded-xl border border-border p-6 text-sm text-ink-dim">
              No records on this page. Try a different collection or search.
            </p>
          ) : (
            rows.map((row) => (
              <button
                key={String(row.id)}
                onClick={() => setInspect({ kind, id: String(row.id) })}
                className="block w-full rounded-xl border border-border bg-surface p-4 text-left hover:border-border-strong"
              >
                <p className="text-[11px] text-ink-faint">
                  {String(row.type || row.finding_type)} ·{" "}
                  {String(row.confidence || "not recorded")} ·{" "}
                  {String(row.source_tool || "source not recorded")}
                </p>
                <p className="mt-1 break-all text-sm text-ink">
                  {String(row.title || row.target || row.id)}
                </p>
                <p className="mt-1 break-all font-mono text-[11px] text-ink-faint">
                  {String(row.id)} · {String(row.target || "")}
                </p>
              </button>
            ))
          )}
        </div>
      )}
      <div className="mt-4 flex items-center justify-end gap-3 text-xs">
        <span className="mr-auto text-ink-faint">
          40 records per page · searches run against the engagement store
        </span>
        <button
          className="btn-ghost"
          disabled={!page || resource.loading}
          onClick={() => setPage(page - 1)}
        >
          Previous
        </button>
        <span>Page {page + 1}</span>
        <button
          className="btn-ghost"
          disabled={rows.length < 40 || resource.loading}
          onClick={() => setPage(page + 1)}
        >
          Next
        </button>
      </div>
      {inspect && (
        <RecordInspector
          engagementId={engagementId}
          records={[inspect]}
          title={inspect.id}
          onClose={() => setInspect(null)}
        />
      )}
    </div>
  );
}
