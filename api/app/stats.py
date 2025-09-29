from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .metrics_collector import metrics_collector


@dataclass
class DevStats:
    """Maintains basic in-memory stats, primarily for the /dev dashboard."""

    total_requests: int = 0
    total_with_risk: int = 0
    recent: List[Dict[str, Any]] = field(default_factory=list)

    def add(
        self, *, request_id: str, risk_score: int, threats: List[Dict[str, Any]], latency_ms: float
    ):
        """
        Adds a new request to the stats and forwards it to the metrics collector.
        """
        self.total_requests += 1
        if risk_score > 0 or len(threats) > 0:
            self.total_with_risk += 1
        
        # Keep a list of recent requests for the dev dashboard
        self.recent.insert(
            0,
            {
                "request_id": request_id,
                "risk_score": risk_score,
                "threats": threats,
                "latency_ms": latency_ms,
            },
        )
        if len(self.recent) > 50:
            self.recent.pop()

        # --- Integration with the new MetricsCollector ---
        # This is where the old stats system feeds into the new one.
        metrics_collector.record_request(status_code=200, latency_ms=latency_ms)
        metrics_collector.record_analysis(risk_score=risk_score, threats=threats)

    def record_error(self, status_code: int, latency_ms: float):
        """
        Records an error request.
        """
        self.total_requests += 1
        metrics_collector.record_request(status_code=status_code, latency_ms=latency_ms)


# Singleton instance
stats = DevStats()