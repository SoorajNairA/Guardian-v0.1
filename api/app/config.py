import os
from typing import List


class Settings:
    def __init__(self) -> None:
        self.environment = os.getenv("ENV", "development")

        # Auth
        self.guardian_api_key = os.getenv("GUARDIAN_API_KEY", "")
        self.guardian_api_keys = self._split_env_list(os.getenv("GUARDIAN_API_KEYS", ""))

        # Gemini
        self.gemini_api_key = os.getenv("GEMINI_API_KEY", "")
        self.gemini_model = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

        # Supabase
        self.supabase_url = os.getenv("SUPABASE_URL", "")
        self.supabase_anon_key = os.getenv("SUPABASE_ANON_KEY", "")
        self.supabase_service_role_key = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

        # Redis
        self.redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.redis_password = os.getenv("REDIS_PASSWORD", "")
        self.redis_ssl = os.getenv("REDIS_SSL", "False").lower() in ("true", "1", "t")
        self.redis_max_connections = int(os.getenv("REDIS_MAX_CONNECTIONS", "10"))
        self.redis_socket_timeout = int(os.getenv("REDIS_SOCKET_TIMEOUT", "5"))

        # Rate Limiting
        self.rate_limit_enabled = os.getenv("RATE_LIMIT_ENABLED", "True").lower() in ("true", "1", "t")
        self.rate_limit_fallback_to_memory = os.getenv("RATE_LIMIT_FALLBACK_TO_MEMORY", "True").lower() in ("true", "1", "t")
        self.default_rate_limit_per_key = int(os.getenv("DEFAULT_RATE_LIMIT_PER_KEY", "100"))
        self.default_rate_limit_per_ip = int(os.getenv("DEFAULT_RATE_LIMIT_PER_IP", "1000"))
        self.rate_limit_window_seconds = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))

        # Logging
        self.log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        self.log_to_file = os.getenv("LOG_TO_FILE", "False").lower() in ("true", "1", "t")
        self.log_file_path = os.getenv("LOG_FILE_PATH", "/var/log/guardian/app.log")
        self.log_max_size_mb = int(os.getenv("LOG_MAX_SIZE_MB", "100"))
        self.log_backup_count = int(os.getenv("LOG_BACKUP_COUNT", "5"))

        # Health Checks
        self.health_check_timeout_seconds = int(os.getenv("HEALTH_CHECK_TIMEOUT_SECONDS", "5"))
        self.health_check_supabase_enabled = os.getenv("HEALTH_CHECK_SUPABASE_ENABLED", "True").lower() in ("true", "1", "t")
        self.health_check_redis_enabled = os.getenv("HEALTH_CHECK_REDIS_ENABLED", "True").lower() in ("true", "1", "t")
        self.health_check_gemini_enabled = os.getenv("HEALTH_CHECK_GEMINI_ENABLED", "True").lower() in ("true", "1", "t")

        # Metrics
        self.metrics_enabled = os.getenv("METRICS_ENABLED", "True").lower() in ("true", "1", "t")
        self.metrics_collection_interval_seconds = int(os.getenv("METRICS_COLLECTION_INTERVAL_SECONDS", "60"))
        self.prometheus_metrics_enabled = os.getenv("PROMETHEUS_METRICS_ENABLED", "False").lower() in ("true", "1", "t")
        self.prometheus_metrics_port = int(os.getenv("PROMETHEUS_METRICS_PORT", "8001"))

        # Alerting
        self.alerting_enabled = os.getenv("ALERTING_ENABLED", "False").lower() in ("true", "1", "t")
        self.alert_webhook_url = os.getenv("ALERT_WEBHOOK_URL", "")
        self.alert_email_smtp_host = os.getenv("ALERT_EMAIL_SMTP_HOST", "")
        self.alert_email_from = os.getenv("ALERT_EMAIL_FROM", "")
        self.alert_email_to = os.getenv("ALERT_EMAIL_TO", "")
        self.alert_critical_error_threshold = int(os.getenv("ALERT_CRITICAL_ERROR_THRESHOLD", "10"))
        self.alert_latency_threshold_ms = int(os.getenv("ALERT_LATENCY_THRESHOLD_MS", "5000"))
        self.alert_error_rate_threshold_percent = float(os.getenv("ALERT_ERROR_RATE_THRESHOLD_PERCENT", "5.0"))

    @staticmethod
    def _split_env_list(value: str) -> List[str]:
        return [v for v in value.split(",") if v]


settings = Settings()
