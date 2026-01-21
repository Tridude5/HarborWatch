from typing import Any, Dict, Optional

class TLSNoSNIDetector:
    rule_id = "TLS_NO_SNI"
    rule_name = "TLS without SNI"
    severity = "low"

    def process(self, event: Dict[str, Any], event_os_id: str) -> Optional[Dict[str, Any]]:
        if event.get("event_type") not in ("ssl", "tls"):
            return None

        raw = event.get("raw", {})
        src = event.get("src_ip")
        dst = event.get("dst_ip")
        dst_port = event.get("dst_port")

        # Zeek: ssl.log often has "server_name" for SNI
        sni = raw.get("server_name")

        if not src or not dst or not dst_port:
            return None

        # If sni missing/empty on external-like TLS, flag lightly.
        if sni is None or str(sni).strip() == "":
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "ts": event["ts"],
                "summary": f"TLS connection without SNI: {src} -> {dst}:{dst_port}",
                "reason": "Observed a TLS handshake where the Server Name Indication (SNI) field was not present; this can appear in malware tooling or non-browser clients.",
                "entity": {"type": "flow", "src_ip": src, "dst_ip": dst, "dst_port": dst_port},
                "factors": [
                    {"factor": "missing_sni", "value": True, "weight": 1.0},
                ],
                "evidence": [{"event_id": event_os_id, "note": "TLS handshake event"}],
            }

        return None
