import React, { useState } from "react";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";

export default function App() {
  const [selected, setSelected] = useState<string | null>(null);

  return (
    <div className="container">
      <h1>HarborWatch</h1>
      <p className="mono">Zeek-based detection + triage console (v1)</p>

      {!selected ? (
        <Alerts onSelect={setSelected} />
      ) : (
        <>
          <button onClick={() => setSelected(null)}>Back to Alerts</button>
          <AlertDetail alertId={selected} />
        </>
      )}
    </div>
  );
}
