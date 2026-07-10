import { useCallback, useEffect, useState } from 'react'
import { fetchStatus } from './api'
import StatCard from './components/StatCard'
import RulesPanel from './components/RulesPanel'
import StatusBadge from './components/StatusBadge'

const POLL_INTERVAL_MS = 3000

export default function App() {
  const [status, setStatus] = useState(null)
  const [error, setError] = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)

  const load = useCallback(async () => {
    try {
      const data = await fetchStatus()
      setStatus(data)
      setError(null)
      setLastUpdated(new Date())
    } catch (err) {
      setError(err.message)
    }
  }, [])

  useEffect(() => {
    load()
    const id = setInterval(load, POLL_INTERVAL_MS)
    return () => clearInterval(id)
  }, [load])

  const connected = status !== null && error === null

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-5xl px-6 py-10">
        <header className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight text-white">
              Sentinel<span className="text-cyan-400">DB</span>
            </h1>
            <p className="mt-1 text-sm text-slate-400">
              PostgreSQL Firewall Gateway — Canlı İzleme Paneli
            </p>
          </div>
          <StatusBadge connected={connected} />
        </header>

        {error && (
          <div className="mt-6 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-300">
            API'ye ulaşılamadı ({error}). Gateway çalışıyor mu?{' '}
            <code className="font-mono">localhost:8080/api/status</code>
          </div>
        )}

        <main className="mt-8 grid gap-6 sm:grid-cols-2">
          <StatCard
            label="Toplam Bağlantı"
            value={status ? status.connections_total : '—'}
            icon="🔌"
            accent="bg-cyan-500"
          />
          <StatCard
            label="Engellenen Sorgu"
            value={status ? status.blocked_queries_total : '—'}
            icon="⛔"
            accent="bg-red-500"
          />
        </main>

        <div className="mt-6">
          <RulesPanel rules={status ? status.active_rules : []} />
        </div>

        <footer className="mt-8 text-center text-xs text-slate-600">
          {lastUpdated
            ? `Son güncelleme: ${lastUpdated.toLocaleTimeString('tr-TR')} · her ${POLL_INTERVAL_MS / 1000} saniyede bir yenilenir`
            : 'Yükleniyor…'}
        </footer>
      </div>
    </div>
  )
}
