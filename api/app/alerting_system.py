import asyncio
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, Optional

import httpx

from .config import settings
from .structured_logging import get_logger, log_alert

logger = get_logger("guardian.alerting_system")


@dataclass
class Alert:
    """Represents an active alert."""

    name: str
    reason: str
    last_triggered: float = field(default_factory=time.time)
    triggered_count: int = 1
    is_resolved: bool = False


class AlertingSystem:
    """Manages alert rules and notifications."""

    def __init__(self, cooldown_seconds: int = 300):
        self.cooldown_seconds = cooldown_seconds
        self._active_alerts: Dict[str, Alert] = {}
        self._http_client = httpx.AsyncClient(timeout=10.0)

    def check_and_trigger(self, metrics: dict, health_statuses: list):
        """Evaluates all alert rules and triggers notifications."""
        if not settings.alerting_enabled:
            return

        # Rule: High Error Rate
        if metrics.get("error_rate_percent", 0) > settings.alert_error_rate_threshold_percent:
            self.trigger_alert(
                "high_error_rate",
                f"Error rate is {metrics['error_rate_percent']:.2f}%, exceeding threshold of {settings.alert_error_rate_threshold_percent}%.",
            )

        # Rule: High Latency
        if metrics.get("p95_latency_ms", 0) > settings.alert_latency_threshold_ms:
            self.trigger_alert(
                "high_latency",
                f"P95 latency is {metrics['p95_latency_ms']:.2f}ms, exceeding threshold of {settings.alert_latency_threshold_ms}ms.",
            )

        # Rule: Unhealthy Dependencies
        for status in health_statuses:
            if not status.is_healthy:
                self.trigger_alert(
                    f"{status.dependency.lower()}_unhealthy",
                    f"{status.dependency} is unhealthy. Reason: {status.error_message or 'N/A'}",
                )

    def trigger_alert(self, name: str, reason: str):
        """Triggers an alert, respecting cooldown periods."""
        now = time.time()
        if name in self._active_alerts:
            alert = self._active_alerts[name]
            if not alert.is_resolved and (now - alert.last_triggered) < self.cooldown_seconds:
                logger.debug(f"Alert '{name}' is in cooldown. Skipping.")
                return
            alert.last_triggered = now
            alert.triggered_count += 1
            alert.is_resolved = False
        else:
            self._active_alerts[name] = Alert(name=name, reason=reason)

        log_alert(logger, alert_name=name, reason=reason)
        asyncio.create_task(self.send_notifications(name, reason))

    def resolve_alert(self, name: str):
        """Marks an alert as resolved."""
        if name in self._active_alerts:
            self._active_alerts[name].is_resolved = True
            logger.info(f"Alert '{name}' has been marked as resolved.")

    async def send_notifications(self, name: str, reason: str):
        """Sends notifications via configured channels."""
        if settings.alert_webhook_url:
            await self.send_webhook(name, reason)
        # Email and other notification channels can be added here

    async def send_webhook(self, name: str, reason: str):
        """Sends an alert to a webhook URL."""
        payload = {
            "alert_name": name,
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
            "environment": settings.environment,
        }
        try:
            response = await self._http_client.post(settings.alert_webhook_url, json=payload)
            response.raise_for_status()
            logger.info(f"Successfully sent webhook for alert '{name}'.")
        except Exception as e:
            logger.error(f"Failed to send webhook for alert '{name}'", error=str(e))

    def get_active_alerts(self) -> list:
        """Returns a list of currently active (unresolved) alerts."""
        return [
            alert
            for alert in self._active_alerts.values()
            if not alert.is_resolved
        ]

# Singleton instance
alerting_system = AlertingSystem()
