import time
from collections import deque
from threading import Lock

from prometheus_client import Counter, Gauge, Histogram

from .config import settings

# --- Prometheus Metrics ---
# These are defined globally to be accessible across the application.

REQUEST_COUNT = Counter(
    "guardian_requests_total",
    "Total number of requests by method, path, and status code.",
    ["method", "path", "status_code"],
)

REQUEST_LATENCY = Histogram(
    "guardian_request_latency_seconds",
    "Request latency in seconds.",
    ["method", "path"],
)

RISK_SCORE_SUMMARY = Histogram(
    "guardian_analysis_risk_score",
    "Distribution of analysis risk scores.",
)

THREATS_DETECTED_COUNT = Counter(
    "guardian_analysis_threats_detected_total",
    "Total number of detected threats by category.",
    ["category"],
)

# --- In-Memory Metrics Collector ---

class MetricsCollector:
    """Collects and manages application metrics in memory."""

    def __init__(self):
        self._lock = Lock()
        self.reset()

    def reset(self):
        """Resets all in-memory metrics."""
        with self._lock:
            self.total_requests = 0
            self.error_count = 0
            self.latencies = deque(maxlen=1000)  # Store last 1000 latencies
            self.risk_scores = deque(maxlen=1000)

    def record_request(self, status_code: int, latency_ms: float):
        """Records a completed request."""
        with self._lock:
            self.total_requests += 1
            if status_code >= 400:
                self.error_count += 1
            self.latencies.append(latency_ms)

        # Update Prometheus metrics if enabled
        if settings.prometheus_metrics_enabled:
            REQUEST_LATENCY.labels(method="POST", path="/v1/analyze").observe(latency_ms / 1000)
            REQUEST_COUNT.labels(method="POST", path="/v1/analyze", status_code=status_code).inc()

    def record_analysis(self, risk_score: int, threats: list):
        """Records details of a completed analysis."""
        with self._lock:
            self.risk_scores.append(risk_score)
        
        if settings.prometheus_metrics_enabled:
            RISK_SCORE_SUMMARY.observe(risk_score)
            for threat in threats:
                THREATS_DETECTED_COUNT.labels(category=threat.get("category", "unknown")).inc()

    def get_summary(self) -> dict:
        """Returns a summary of current in-memory metrics."""
        with self._lock:
            if not self.latencies:
                avg_latency = 0
            else:
                avg_latency = sum(self.latencies) / len(self.latencies)

            error_rate = (self.error_count / self.total_requests) * 100 if self.total_requests > 0 else 0

            return {
                "total_requests": self.total_requests,
                "error_count": self.error_count,
                "error_rate_percent": round(error_rate, 2),
                "average_latency_ms": round(avg_latency, 2),
                "p95_latency_ms": self._calculate_percentile(self.latencies, 95),
            }

    def _calculate_percentile(self, data: deque, percentile: int) -> float:
        """Calculates a percentile from a deque of numbers."""
        if not data:
            return 0.0
        
        sorted_data = sorted(list(data))
        index = (percentile / 100) * (len(sorted_data) - 1)
        
        if index.is_integer():
            return round(sorted_data[int(index)], 2)
        else:
            lower = sorted_data[int(index)]
            upper = sorted_data[int(index) + 1]
            return round(lower + (index % 1) * (upper - lower), 2)

# Singleton instance
metrics_collector = MetricsCollector()
