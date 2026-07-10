export default function StatusBadge({ connected }) {
  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium ${
        connected
          ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
          : 'border-red-500/30 bg-red-500/10 text-red-300'
      }`}
    >
      <span
        className={`h-2 w-2 rounded-full ${connected ? 'animate-pulse bg-emerald-400' : 'bg-red-400'}`}
      />
      {connected ? 'Gateway Bağlı' : 'Gateway Bağlantısı Yok'}
    </span>
  )
}
