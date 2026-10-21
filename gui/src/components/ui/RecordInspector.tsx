"use client";

import { useEffect, useRef, useState } from "react";
import { X } from "lucide-react";
import type { RecordReference } from "@/lib/types";
import { getRecord } from "@/lib/api";
import { useResource } from "@/hooks/useResource";
import { ErrorState, Loading } from "./States";

/** Load original records only when requested; inventory summaries stay light. */
export function RecordInspector({
  engagementId,
  records,
  title,
  onClose,
}: {
  engagementId: string;
  records: RecordReference[];
  title: string;
  onClose: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [index, setIndex] = useState(0);
  const record = records[index] || records[0]!;
  const resource = useResource(
    (signal) => getRecord(engagementId, record, signal),
    [engagementId, record.kind, record.id],
  );
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  return (
    <dialog
      ref={dialog}
      onCancel={onClose}
      aria-label="Original evidence record"
      className="m-auto max-h-[85vh] w-[min(900px,95vw)] overflow-y-auto rounded-2xl border border-border bg-surface p-5 text-ink shadow-lift backdrop:bg-black/60"
    >
      <header className="mb-4 flex items-start justify-between gap-4">
        <div>
          <p className="text-xs uppercase tracking-wider text-amber">
            Original evidence · read only
          </p>
          <h2 className="mt-1 break-all text-lg font-semibold">{title}</h2>
        </div>
        <button
          autoFocus
          onClick={onClose}
          aria-label="Close evidence"
          className="btn-ghost"
        >
          <X size={18} />
        </button>
      </header>
      <label className="mb-4 block text-xs text-ink-dim">
        Source record ({records.length})
        <select
          aria-label="Source record"
          value={index}
          onChange={(e) => setIndex(Number(e.target.value))}
          className="mt-1 block w-full rounded-lg border border-border bg-base p-2 font-mono"
        >
          {records.map((ref, i) => (
            <option key={`${ref.kind}:${ref.id}`} value={i}>
              {ref.kind} · {ref.id}
            </option>
          ))}
        </select>
      </label>
      {resource.loading ? (
        <Loading label="Loading complete record…" />
      ) : resource.error ? (
        <ErrorState message={resource.error} onRetry={resource.refetch} />
      ) : (
        <>
          <dl className="grid gap-2 text-sm sm:grid-cols-2">
            {[
              "type",
              "finding_type",
              "asset_type",
              "target",
              "confidence",
              "source_tool",
              "created_at",
              "updated_at",
              "last_seen_at",
              "evidence_id",
              "occurrence_count",
            ]
              .filter(
                (key) =>
                  resource.data?.[key] != null && resource.data[key] !== "",
              )
              .map((key) => (
                <div key={key}>
                  <dt className="text-xs text-ink-faint">
                    {key.replaceAll("_", " ")}
                  </dt>
                  <dd className="break-all font-mono text-xs">
                    {String(resource.data?.[key])}
                  </dd>
                </div>
              ))}
          </dl>
          {["description", "evidence", "details", "metadata"]
            .filter(
              (key) =>
                resource.data?.[key] &&
                Object.keys(Object(resource.data[key])).length,
            )
            .map((key) => (
              <section className="mt-4" key={key}>
                <h3 className="mb-2 text-sm font-semibold capitalize">{key}</h3>
                <pre className="overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border bg-base p-3 text-xs">
                  {typeof resource.data?.[key] === "string"
                    ? String(resource.data[key])
                    : JSON.stringify(resource.data?.[key], null, 2)}
                </pre>
              </section>
            ))}
          <details className="mt-5">
            <summary className="cursor-pointer text-xs text-ink-dim">
              Complete stored record (JSON)
            </summary>
            <pre className="mt-2 overflow-auto whitespace-pre-wrap break-all text-xs">
              {JSON.stringify(resource.data, null, 2)}
            </pre>
          </details>
        </>
      )}
    </dialog>
  );
}
