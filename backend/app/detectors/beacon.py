import math
from collections import defaultdict, deque
from typing import Any, Dict, Optional, Tuple

class BeaconDetector:
    rule_id = "CONN_BEACONING"
    rule_name = "Periodic beacon-like connections"
    severity = "high"

    # Need enough repeats to be credible
    min_hits = 12
    window_sec = 30 * 60  # 30 minutes
    max_jitter_ratio = 0.12  # stddev/mean of inter-arrival times

    def __init__(self) -> None:
        # key: (src, dst, dport, proto) -> deque[(ts, event_id)]
        self.flows: Dict[Tuple[str, str, int, str], deque] = defaultdict(deque)

    def process(self, event: Dict[str, Any], event_os_id: str) -> Optional[Dict[str, Any]]:
        if event.get("event_type") != "conn":
            return None

        src = event.get("src_ip")
        dst = event.get("dst_ip")
        dport = event.get("dst_port")
        proto = event.get("proto") or "?"
        if not (src and dst and dport):
            return None

        ts = float(event["ts"])
        key = (src, dst, int(dport), str(proto))
        q = self.flows[key]
        q.append((ts, event_os_id))

        # prune to window
        cutoff = ts - self.window_sec
        while q and q[0][0] < cutoff:
            q.popleft()

        if len(q) < self.min_hits:
            return None

        times = [t for t, _ in q]
        # inter-arrival times
        dts = [times[i] - times[i-1] for i in range(1, len(times)) if times[i] > times[i-1]]
        if len(dts) < self.min_hits - 1:
            return None

        mean = sum(dts) / len(dts)
        if mean <= 0:
            return None

        var = sum((x - mean) ** 2 for x in dts) / len(dts)
        std = math.sqrt(var)
        jitter_ratio = std / mean

        if jitter_ratio <= self.max_jitter_ratio and mean >= 5:
            evidence = [{"event_id": eid, "note": "Repeated conn event"} for _, eid in list(q)[-12:]]
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "ts": event["ts"],
                "summary": f"Beacon-like traffic: {src} -> {dst}:{dport}/{proto}",
                "reason": f"Observed {len(q)} connections within {self.window_sec/60:.0f} minutes with low timing jitter (std/mean={jitter_ratio:.2f}, avg interval={mean:.1f}s).",
                "entity": {"type": "flow", "src_ip": src, "dst_ip": dst, "dst_port": dport, "proto": proto},
                "factors": [
                    {"factor": "hits_in_window", "value": len(q), "weight": 0.35},
                    {"factor": "avg_interval_sec", "value": round(mean, 2), "weight": 0.35},
                    {"factor": "jitter_ratio", "value": round(jitter_ratio, 3), "weight": 0.30},
                ],
                "evidence": evidence,
            }

        return None
