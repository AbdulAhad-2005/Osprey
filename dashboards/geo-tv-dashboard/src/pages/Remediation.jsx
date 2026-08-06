import { useMemo } from 'react'
import { Wrench, ArrowRight, Clock } from 'lucide-react'
import { SeverityBadge, Tag } from '../components/Badge'
import { findings, severityMeta } from '../data/engagement'

const sevOrder = ['high', 'medium', 'low', 'info']
const prioMeta = {
  high: { label: 'P0 — Immediate', desc: 'Act within days: internet-exposed, unpatched, or actively-listed risk.' },
  medium: { label: 'P1 — Short term', desc: 'Schedule within weeks: patch lag, disclosure, and auth-control gaps.' },
  low: { label: 'P2 — Plan', desc: 'Plan within the next hardening cycle.' },
  info: { label: 'P3 — Hygiene', desc: 'Housekeeping, monitoring aids, and documentation.' },
}

export default function Remediation() {
  const groups = useMemo(() => {
    const g = {}
    for (const s of sevOrder) g[s] = findings.filter(f => f.severity === s)
    return g
  }, [])

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-slate-900">Remediation Roadmap</h2>
        <p className="text-[12px] text-slate-500">
          Concrete fix for every confirmed finding, ordered by priority. Items marked with the clock are patch-lag
          items that should be re-verified after applying updates.
        </p>
      </div>

      {sevOrder.map(sev => (
        <section key={sev} className="space-y-3">
          <div
            className="glass card-shadow rounded-2xl px-5 py-4 flex items-center gap-4"
            style={{ borderLeft: `4px solid ${severityMeta[sev].color}` }}
          >
            <div
              className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
              style={{ background: severityMeta[sev].bg, border: `1px solid ${severityMeta[sev].ring}` }}
            >
              <Wrench className="w-4 h-4" style={{ color: severityMeta[sev].color }} />
            </div>
            <div className="min-w-0 flex-1">
              <div className="font-bold text-slate-900 text-sm">{prioMeta[sev].label}</div>
              <div className="text-[12px] text-slate-500">{prioMeta[sev].desc}</div>
            </div>
            <span className="text-[11px] font-semibold text-slate-400 shrink-0">{groups[sev].length} item(s)</span>
          </div>

          <div className="space-y-3">
            {groups[sev].map(f => (
              <div key={f.id} className="glass card-shadow rounded-2xl p-5 animate-float-in">
                <div className="flex items-start gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SeverityBadge severity={f.severity} size="sm" />
                      <span className="text-[11px] font-mono text-slate-400">{f.id}</span>
                    </div>
                    <h4 className="font-semibold text-slate-800 text-sm mt-2 leading-snug">{f.title}</h4>
                    <div className="text-[12px] text-slate-500 mt-0.5 font-mono">{f.host}</div>
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {f.tags.map(t => <Tag key={t}>{t}</Tag>)}
                    </div>
                  </div>
                </div>
                <div className="mt-3 rounded-xl bg-emerald-50 border border-emerald-200 px-3.5 py-3">
                  <div className="text-[11px] font-bold text-emerald-700 uppercase tracking-wide mb-1 flex items-center gap-1.5">
                    <ArrowRight className="w-3 h-3" /> Remediation
                  </div>
                  <div className="text-sm leading-relaxed text-emerald-900">{f.remediation}</div>
                </div>
              </div>
            ))}
          </div>
        </section>
      ))}

      <div className="glass card-shadow rounded-2xl px-5 py-4 flex items-center gap-4">
        <div className="w-9 h-9 rounded-xl bg-amber-50 border border-amber-200 flex items-center justify-center shrink-0">
          <Clock className="w-4 h-4 text-amber-600" />
        </div>
        <p className="text-[12.5px] text-slate-500 leading-relaxed">
          Re-verification notes: after applying Exchange SU10 (F36) re-check <code className="font-mono">X-OWA-Version</code>
          on autodiscover.geo.tv — it must move past 15.2.1748.39. After WordPress core/plugin upgrades (F32/F41) re-run the
          wp-json user enumeration check to confirm enumeration stays disabled. Items F40, F42, F43, F44, F45 and F46 require
          no action beyond the notes attached to them.
        </p>
      </div>
    </div>
  )
}
