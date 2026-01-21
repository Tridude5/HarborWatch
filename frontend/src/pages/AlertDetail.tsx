import React, { useEffect, useState } from "react";
import { fetchAlert } from "../api";

export default function AlertDetail({ alertId }: { alertId: string }) {
  const [alert, setAlert] = useState<any | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      setErr(null);
      try {
        const a = await fetchAlert(alertId);
        setAlert(a);
      } catch (e: any) {
        setErr(String(e?.message || e));
      }
    })();
  }, [alertId]);

  if (err) return <div className="card">Error: {err}</div>;
  if (!alert) return <div className="card">Loading...</div>;

  return (
    <div className="card">
      <h2 style={{ marginTop: 0 }}>{alert.rule_name}</h2>
      <div><b>Summary:</b> {alert.summary}</div>
      <div style={{ marginTop: 8 }}><b>Reason:</b> {alert.reason}</div>

      <div style={{ marginTop: 14 }}>
        <b>Entity</b>
        <pre className="mono">{JSON.stringify(alert.entity, null, 2)}</pre>
      </div>

      <div style={{ marginTop: 14 }}>
        <b>Explainability factors</b>
        {(!alert.factors || alert.factors.length === 0) ? (
          <div className="mono">None</div>
        ) : (
          <pre className="mono">{JSON.stringify(alert.factors, null, 2)}</pre>
        )}
      </div>

      <div style={{ marginTop: 14 }}>
        <b>Evidence</b>
        {(!alert.evidence || alert.evidence.length === 0) ? (
          <div className="mono">None</div>
        ) : (
          <pre className="mono">{JSON.stringify(alert.evidence, null, 2)}</pre>
        )}
      </div>
    </div>
  );
}
