const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8080'

// fetchStatus, gateway'in /api/status endpoint'inden güncel bağlantı/
// engelleme sayaçlarını ve aktif firewall kurallarını okur.
export async function fetchStatus() {
  const res = await fetch(`${API_BASE_URL}/api/status`)
  if (!res.ok) {
    throw new Error(`API ${res.status} döndürdü`)
  }
  return res.json()
}
