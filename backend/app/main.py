from fastapi import FastAPI, Header, HTTPException
from typing import Any, Dict, Optional
import uuid

from .config import API_KEY
from .opensearch_client import get_client
from .storage import init_storage, index_event, index_alert, search_alerts, get_alert
from .detectors import build_detectors

app = FastAPI(title="HarborWatch API", version="0.1.0")

client = get_client()
init_storage(client)
detectors = build_detectors()

def require_auth(authorization: Optional[str]) -> None:
    # Expect: "Bearer <key>"
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization Bearer token")
    token = authorization.split(" ", 1)[1].strip()
    if token != API_KEY:
        raise HTTPException(status_code=403, detail="Invalid API key")

def normalize_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    # Infer event_type from Zeek log name (conn.log, dns.log, ssl.log, http.log)
    source_file = str(payload.get("source_file", ""))
    event_type = "unknown"
    if source_file.endswith("conn.log"):
        event_type = "conn"
    elif source_file.endswith("dns.log"):
        event_type = "dns"
    elif source_file.endswith("ssl.log") or source_file.endswith("tls.log"):
        event_type = "ssl"
    elif source_file.endswith("http.log"):
        event_type = "http"

    ts = payload.get("ts")
    if ts is None:
        # Zeek JSON always has ts; if missing, we reject
        raise ValueError("Missing ts")

    # Zeek: id.orig_h / id.orig_p / id.resp_h / id.resp_p
    orig_h = payload.get("id.orig_h")
    orig_p = payload.get("id.orig_p")
    resp_h = payload.get("id.resp_h")
    resp_p = payload.get("id.resp_p")

    # Zeek: proto is sometimes 'proto' or 'transport_proto'
    proto = payload.get("proto") or payload.get("transport_proto")

    return {
        "event_type": event_type,
        "ts": float(ts),
        "uid": payload.get("uid"),
        "src_ip": orig_h,
        "src_port": orig_p,
        "dst_ip": resp_h,
        "dst_port": resp_p,
        "proto": proto,
        "raw": payload,
    }

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/ingest")
def ingest(payload: Dict[str, Any], authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)

    try:
        event = normalize_event(payload)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Bad event: {e}")

    event_id = index_event(client, event)

    # Run detectors inline (simple, works for v1)
    for det in detectors:
        alert = det.process(event, event_id)
        if alert:
            # ensure alert_id
            alert.setdefault("alert_id", str(uuid.uuid4()))
            index_alert(client, alert)

    return {"indexed_event_id": event_id}

@app.get("/alerts")
def list_alerts(authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    return {"alerts": search_alerts(client, size=200)}

@app.get("/alerts/{alert_id}")
def read_alert(alert_id: str, authorization: Optional[str] = Header(default=None)):
    require_auth(authorization)
    a = get_alert(client, alert_id)
    if not a:
        raise HTTPException(status_code=404, detail="Alert not found")
    return a
