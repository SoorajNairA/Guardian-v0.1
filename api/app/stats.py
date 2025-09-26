from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class DevStats:
    total_requests: int = 0
    total_with_risk: int = 0
    recent: List[Dict[str, Any]] = field(default_factory=list)

    def add(self, *, request_id: str, risk_score: int, threats: List[Dict[str, Any]]):
        self.total_requests += 1
        if risk_score > 0 or len(threats) > 0:
            self.total_with_risk += 1
        self.recent.insert(0, {
            "request_id": request_id,
            "risk_score": risk_score,
            "threats": threats,
        })
        # Keep only last 50
        if len(self.recent) > 50:
            self.recent = self.recent[:50]


stats = DevStats()


