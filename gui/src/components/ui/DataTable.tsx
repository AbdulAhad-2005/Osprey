"use client";

import { useMemo, useState } from "react";
import { ArrowUpDown, ArrowUp, ArrowDown, Search } from "lucide-react";
import { cn } from "@/lib/cn";

export interface Column<T> {
  key: string;
  header: string;
  cell: (row: T) => React.ReactNode;
  /** Sort accessor; omit to make the column unsortable. */
  sortKey?: (row: T) => string | number;
  className?: string;
  align?: "left" | "right";
}

export function DataTable<T>({
  rows,
  columns,
  getRowKey,
  filter,
  searchPlaceholder = "Filter…",
  initialSort,
  onRowClick,
  dense,
}: {
  rows: T[];
  columns: Column<T>[];
  getRowKey: (row: T, i: number) => string;
  filter?: (row: T, q: string) => boolean;
  searchPlaceholder?: string;
  initialSort?: { key: string; dir: "asc" | "desc" };
  onRowClick?: (row: T) => void;
  dense?: boolean;
}) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<{ key: string; dir: "asc" | "desc" } | null>(initialSort ?? null);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    let out = needle && filter ? rows.filter((r) => filter(r, needle)) : rows;
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      if (col?.sortKey) {
        const acc = col.sortKey;
        out = [...out].sort((a, b) => {
          const va = acc(a);
          const vb = acc(b);
          const cmp = typeof va === "number" && typeof vb === "number" ? va - vb : String(va).localeCompare(String(vb));
          return sort.dir === "asc" ? cmp : -cmp;
        });
      }
    }
    return out;
  }, [rows, q, sort, columns, filter]);

  function toggleSort(key: string) {
    setSort((s) =>
      s?.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: "asc" },
    );
  }

  return (
    <div>
      {filter && (
        <div className="mb-2 flex items-center gap-2 rounded-lg border border-border bg-base/50 px-2.5 py-1.5 focus-within:border-border-strong sm:max-w-xs">
          <Search size={13} className="text-ink-faint" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder={searchPlaceholder}
            className="w-full bg-transparent text-[12.5px] text-ink placeholder:text-ink-faint focus:outline-none"
          />
          {q && (
            <span className="font-mono text-[10.5px] text-ink-faint">
              {filtered.length}/{rows.length}
            </span>
          )}
        </div>
      )}
      <div className="overflow-x-auto rounded-xl border border-border">
        <table className="w-full border-collapse text-[13px]">
          <thead>
            <tr className="bg-surface-2">
              {columns.map((c) => (
                <th
                  key={c.key}
                  className={cn(
                    "border-b border-border px-3 py-2 text-left font-medium text-ink-dim",
                    c.align === "right" && "text-right",
                    c.sortKey && "cursor-pointer select-none hover:text-ink",
                  )}
                  onClick={() => c.sortKey && toggleSort(c.key)}
                >
                  <span className={cn("inline-flex items-center gap-1", c.align === "right" && "flex-row-reverse")}>
                    {c.header}
                    {c.sortKey &&
                      (sort?.key === c.key ? (
                        sort.dir === "asc" ? (
                          <ArrowUp size={11} className="text-amber" />
                        ) : (
                          <ArrowDown size={11} className="text-amber" />
                        )
                      ) : (
                        <ArrowUpDown size={11} className="text-ink-faint/60" />
                      ))}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map((row, i) => (
              <tr
                key={getRowKey(row, i)}
                onClick={() => onRowClick?.(row)}
                className={cn(
                  "border-b border-border/60 last:border-0 transition-colors",
                  onRowClick && "cursor-pointer hover:bg-white/[0.025]",
                )}
              >
                {columns.map((c) => (
                  <td
                    key={c.key}
                    className={cn(
                      "px-3 align-top text-ink-dim",
                      dense ? "py-1.5" : "py-2.5",
                      c.align === "right" && "text-right",
                      c.className,
                    )}
                  >
                    {c.cell(row)}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
