export default function StatCard({ label, value, icon, accent }) {
  return (
    <div className="relative overflow-hidden rounded-2xl border border-slate-800 bg-slate-900/60 p-6 shadow-lg backdrop-blur">
      <div className={`absolute -right-8 -top-8 h-28 w-28 rounded-full ${accent} opacity-20 blur-2xl`} />
      <div className="relative flex items-center gap-2 text-slate-400">
        <span className="text-lg leading-none">{icon}</span>
        <span className="text-sm font-medium uppercase tracking-wider">{label}</span>
      </div>
      <p className="relative mt-4 text-4xl font-semibold tabular-nums text-white">{value}</p>
    </div>
  )
}
