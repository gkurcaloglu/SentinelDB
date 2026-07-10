export default function RulesPanel({ rules }) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-6 shadow-lg backdrop-blur">
      <div className="flex items-center gap-2 text-slate-400">
        <span className="text-lg leading-none">🛡️</span>
        <h2 className="text-sm font-medium uppercase tracking-wider">
          Aktif Firewall Kuralları (Wasm)
        </h2>
      </div>

      {rules.length === 0 ? (
        <p className="mt-4 text-sm text-slate-500">Tanımlı kural yok.</p>
      ) : (
        <ul className="mt-4 flex flex-wrap gap-2">
          {rules.map((rule) => (
            <li
              key={rule}
              className="rounded-full border border-red-500/30 bg-red-500/10 px-3 py-1 font-mono text-xs text-red-300"
            >
              {rule}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
