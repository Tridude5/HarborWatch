from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

class Event(BaseModel):
    event_type: str
    ts: float = Field(..., description="epoch seconds")
    uid: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    raw: Dict[str, Any] = Field(default_factory=dict)

class ExplainFactor(BaseModel):
    factor: str
    value: Any
    weight: float

class Alert(BaseModel):
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    ts: float
    summary: str
    reason: str
    entity: Dict[str, Any]
    factors: List[ExplainFactor] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)  # event pointers
