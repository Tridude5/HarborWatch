import React, { useEffect, useState } from "react";
import { fetchAlerts } from "../api";

function sevClass(sev: string) {
  const s = (sev || "").toLowerCase();
  if (s === "high") return "badge high";
  if (s === "medium") return "badge medium";
  return "badge low";
}

export default function Alerts({ onSelect }: { onSelect: (id: string) => void }) {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    setErr(null);
    try {
      const a = await fetchAlerts();
      setAlerts(a);
    } catch (e: any) {
      setErr(String(e?.message || e));
    }
  }

  useEffect(() => { load(); }, []);

  return (
    <div>
      <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
        <h2>Alerts</h2>
        <button onClick={load}>Refresh</button>
      </div>

      {err && <div className="card">Error: {err}</div>}
      {alerts.length === 0 && <div className="card">No alerts yet.</div>}

      {alerts.map((a) => (
        <div className="card" key={a.alert_id}>
          <div className="row" style={{ justifyContent: "space-between" }}>
            <div>
              <div className={sevClass(a.severity)}>{(a.severity || "low").toUpperCase()}</div>
              <h3 style={{ margin: "10px 0 6px" }}>{a.rule_name}</h3>
              <div>{a.summary}</div>
              <div className="mono" style={{ marginTop: 8 }}>
                alert_id: {a.alert_id}
              </div>
            </div>
            <div>
              <button onClick={() => onSelect(a.alert_id)}>Open</button>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}
