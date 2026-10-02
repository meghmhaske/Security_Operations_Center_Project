from pydantic import BaseModel, Field
from typing import Optional, Literal

EventType = Literal[
    "failed_login",
    "successful_login",
    "privilege_escalation",
    "data_transfer",
    "web_request",
    "network_connection",
]

SourceType = Literal["windows", "linux", "web", "firewall", "simulator"]

class SecurityEvent(BaseModel):
    timestamp: str
    source_type: SourceType
    event_type: EventType
    source_ip: str
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    destination_port: Optional[int] = Field(default=None, ge=1, le=65535)
    protocol: Optional[str] = None
    status: Optional[str] = None
    bytes_transferred: int = Field(default=0, ge=0)
    metadata: dict = Field(default_factory=dict)

class EventResponse(BaseModel):
    event_id: int
    message: str
    risk_score: int
    severity: str
    detections: list[str]
    recommended_action: str
