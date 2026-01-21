const API_BASE = "http://localhost:8000";
const API_KEY = "devkey";

export async function fetchAlerts() {
  const res = await fetch(`${API_BASE}/alerts`, {
    headers: { Authorization: `Bearer ${API_KEY}` }
  });
  if (!res.ok) throw new Error(`Failed alerts: ${res.status}`);
  return (await res.json()).alerts as any[];
}

export async function fetchAlert(alertId: string) {
  const res = await fetch(`${API_BASE}/alerts/${alertId}`, {
    headers: { Authorization: `Bearer ${API_KEY}` }
  });
  if (!res.ok) throw new Error(`Failed alert: ${res.status}`);
  return (await res.json()) as any;
}
