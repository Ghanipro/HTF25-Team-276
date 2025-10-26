from dataclasses import dataclass, asdict
from typing import Dict, Any, Optional
from datetime import datetime
import hashlib

@dataclass
class WAFRequest:
    """HTTP Request model for WAF processing"""
    client_ip: str
    method: str
    url: str
    path: str
    headers: Dict[str, str]
    query_params: Dict[str, Any]
    body: str
    cookies: Dict[str, str]
    timestamp: datetime
    user_agent: str = ""
    content_length: int = 0
    content_type: str = ""
    
    def __post_init__(self):
        self.request_id = self._generate_request_id()
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        unique_string = f"{self.client_ip}{self.method}{self.url}{self.timestamp}"
        return hashlib.md5(unique_string.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return asdict(self)

@dataclass
class WAFResponse:
    """WAF Processing Response"""
    blocked: bool
    threat_level: float
    reason: str
    request_id: str
    timestamp: datetime
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'blocked': self.blocked,
            'threat_level': self.threat_level,
            'reason': self.reason,
            'request_id': self.request_id,
            'timestamp': self.timestamp.isoformat(),
            'details': self.details
        }