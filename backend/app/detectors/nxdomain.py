import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional

class NXDomainDetector:
    rule_id = "DNS_NXDOMAIN_RATE"
    rule_name = "High NXDOMAIN rate"
    severity = "medium"

    # Thresholds tuned for demo; adjust later
    window_sec = 60
    threshold = 40  # NXDOMAINs per minute per src host

    def __init__(self) -> None:
        self.buckets: Dict[str, deque] = defaultdict(deque)

    def process(self, event: Dict[str, Any], event_os_id: str) -> Optional[Dict[str, Any]]:
        if event.get("event_type") != "dns":
            return None

        src = event.get("src_ip")
        if not src:
            return None

        raw = event.get("raw", {})
        rcode_name = raw.get("rcode_name") or raw.get("rcode")
        # Zeek commonly uses rcode_name = "NXDOMAIN"
        if str(rcode_name).upper() != "NXDOMAIN":
            return None

        now = float(event["ts"])
        q = self.buckets[src]
        q.append((now, event_os_id))

        # prune
        cutoff = now - self.window_sec
        while q and q[0][0] < cutoff:
            q.popleft()

        if len(q) >= self.threshold:
            evidence = [{"event_id": eid, "note": "NXDOMAIN DNS response"} for _, eid in list(q)[-10:]]
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "ts": event["ts"],
                "summary": f"{src} generated many NXDOMAIN responses",
                "reason": f"Observed {len(q)} NXDOMAIN responses from {src} in the last {self.window_sec} seconds.",
                "entity": {"type": "host", "ip": src},
                "factors": [
                    {"factor": "window_sec", "value": self.window_sec, "weight": 0.3},
                    {"factor": "nxdomain_count", "value": len(q), "weight": 0.7},
                ],
                "evidence": evidence,
            }

        return None
