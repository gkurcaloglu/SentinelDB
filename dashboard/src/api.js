const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080'

const REQUEST_TIMEOUT_MS = 5000

// fetchStatus, gateway'in /api/status endpoint'inden güncel bağlantı/
// engelleme/maskeleme sayaçlarını ve aktif firewall kurallarını okur.
// İstek REQUEST_TIMEOUT_MS içinde tamamlanmazsa iptal edilir; aksi halde
// gateway yanıt vermediğinde bekleyen fetch'ler poll döngüsünde birikebilir.
export async function fetchStatus() {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  try {
    const res = await fetch(`${API_BASE_URL}/api/status`, { signal: controller.signal })
    if (!res.ok) {
      throw new Error(`API ${res.status} döndürdü`)
    }
    return await res.json()
  } catch (err) {
    if (err.name === 'AbortError') {
      throw new Error('istek zaman aşımına uğradı')
    }
    throw err
  } finally {
    clearTimeout(timeoutId)
  }
}
