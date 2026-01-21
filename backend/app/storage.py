import time
import uuid
from typing import Any, Dict, List, Optional
from opensearchpy import OpenSearch
from .config import EVENTS_INDEX, ALERTS_INDEX

EVENTS_MAPPING = {
  "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
  "mappings": {
    "properties": {
      "ts": {"type": "date", "format": "epoch_second"},
      "event_type": {"type": "keyword"},
      "uid": {"type": "keyword"},
      "src_ip": {"type": "ip"},
      "dst_ip": {"type": "ip"},
      "src_port": {"type": "integer"},
      "dst_port": {"type": "integer"},
      "proto": {"type": "keyword"},
      "raw": {"type": "object", "enabled": True},
      "ingested_at": {"type": "date"}
    }
  }
}

ALERTS_MAPPING = {
  "settings": {"index": {"number_of_shards": 1, "number_of_replicas": 0}},
  "mappings": {
    "properties": {
      "ts": {"type": "date", "format": "epoch_second"},
      "alert_id": {"type": "keyword"},
      "rule_id": {"type": "keyword"},
      "rule_name": {"type": "keyword"},
      "severity": {"type": "keyword"},
      "summary": {"type": "text"},
      "reason": {"type": "text"},
      "entity": {"type": "object", "enabled": True},
      "factors": {"type": "nested"},
      "evidence": {"type": "object", "enabled": True},
      "created_at": {"type": "date"}
    }
  }
}

def ensure_index(client: OpenSearch, index: str, body: Dict[str, Any]) -> None:
    if not client.indices.exists(index=index):
        client.indices.create(index=index, body=body)

def init_storage(client: OpenSearch) -> None:
    ensure_index(client, EVENTS_INDEX, EVENTS_MAPPING)
    ensure_index(client, ALERTS_INDEX, ALERTS_MAPPING)

def index_event(client: OpenSearch, doc: Dict[str, Any]) -> str:
    doc = dict(doc)
    doc["ingested_at"] = int(time.time())
    resp = client.index(index=EVENTS_INDEX, body=doc)
    return resp["_id"]

def index_alert(client: OpenSearch, alert: Dict[str, Any]) -> str:
    alert = dict(alert)
    alert["created_at"] = int(time.time())
    if "alert_id" not in alert:
        alert["alert_id"] = str(uuid.uuid4())
    resp = client.index(index=ALERTS_INDEX, body=alert)
    return resp["_id"]

def search_alerts(client: OpenSearch, size: int = 100) -> List[Dict[str, Any]]:
    resp = client.search(
        index=ALERTS_INDEX,
        body={
            "size": size,
            "sort": [{"ts": {"order": "desc"}}]
        }
    )
    return [h["_source"] | {"_id": h["_id"]} for h in resp["hits"]["hits"]]

def get_alert(client: OpenSearch, alert_id: str) -> Optional[Dict[str, Any]]:
    resp = client.search(
        index=ALERTS_INDEX,
        body={
            "size": 1,
            "query": {"term": {"alert_id": alert_id}}
        }
    )
    hits = resp["hits"]["hits"]
    if not hits:
        return None
    h = hits[0]
    return h["_source"] | {"_id": h["_id"]}
