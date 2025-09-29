import asyncio
import atexit
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from supabase import Client, create_client
from tenacity import retry, stop_after_attempt, wait_exponential

from .config import settings
from .structured_logging import get_logger

logger = get_logger("guardian.logging_client")


@dataclass
class LogEntry:
    """Represents a structured log entry for batch processing."""

    request_id: str
    correlation_id: str
    trace_id: str
    api_key_id: str
    risk_score: int
    text_length: int
    threats: List[Dict[str, Any]] = field(default_factory=list)
    request_meta: Dict[str, Any] = field(default_factory=dict)
    level: str = "INFO"
    message: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class AsyncLoggingClient:
    """Handles asynchronous logging of events to Supabase in the background."""

    def __init__(
        self, batch_size: int = 50, flush_interval: float = 10.0, max_queue_size: int = 10000
    ):
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self._queue: asyncio.Queue[LogEntry] = asyncio.Queue(maxsize=max_queue_size)
        self._supabase: Optional[Client] = self._init_supabase_client()
        self._worker_task: Optional[asyncio.Task] = None
        self._shutdown_event = asyncio.Event()

        atexit.register(self.shutdown)

    def _init_supabase_client(self) -> Optional[Client]:
        """Initializes the Supabase client if configured."""
        if settings.supabase_url and settings.supabase_service_role_key:
            try:
                return create_client(
                    settings.supabase_url, settings.supabase_service_role_key
                )
            except Exception as e:
                logger.error("Failed to initialize Supabase client", error=str(e))
        return None

    def start_worker(self):
        """Starts the background worker task."""
        if self._worker_task is None:
            logger.info("Starting logging client background worker.")
            self._worker_task = asyncio.create_task(self._run_worker())

    async def _run_worker(self):
        """The main loop for the background worker."""
        while not self._shutdown_event.is_set():
            try:
                await asyncio.wait_for(
                    self._shutdown_event.wait(), timeout=self.flush_interval
                )
            except asyncio.TimeoutError:
                pass  # It's time to flush based on interval

            if not self._queue.empty():
                await self._flush_queue()

        # Final flush on shutdown
        await self._flush_queue()

    async def _flush_queue(self):
        """Flushes the queue by processing entries in batches."""
        if not self._supabase:
            logger.warning("Supabase not configured, dropping log entries.")
            # Clear queue to prevent memory leaks
            while not self._queue.empty():
                self._queue.get_nowait()
            return

        batch = []
        while not self._queue.empty() and len(batch) < self.batch_size:
            batch.append(self._queue.get_nowait())

        if batch:
            await self._insert_batch_with_retry(batch)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        before_sleep=lambda s: logger.warning(
            "Retrying Supabase insert", attempt=s.attempt_number
        ),
    )
    async def _insert_batch_with_retry(self, batch: List[LogEntry]):
        """Inserts a batch of log entries into Supabase with retry logic."""
        try:
            payload = [self._format_payload(entry) for entry in batch]
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, lambda: self._supabase.table("logs").insert(payload).execute())
            logger.debug(f"Successfully inserted {len(batch)} log entries.")
        except Exception as e:
            logger.error("Failed to insert log batch into Supabase", error=str(e))
            # For production, you might add these to a dead-letter queue
            raise

    def _format_payload(self, entry: LogEntry) -> Dict[str, Any]:
        """Formats a LogEntry into the dictionary payload for Supabase."""
        return {
            "request_id": entry.request_id,
            "correlation_id": entry.correlation_id,
            "trace_id": entry.trace_id,
            "api_key_id": entry.api_key_id,
            "risk_score": entry.risk_score,
            "text_length": entry.text_length,
            "threats": entry.threats,
            "request_meta": entry.request_meta,
            "level": entry.level,
            "message": entry.message,
            "timestamp": entry.timestamp.isoformat(),
        }

    async def log_event(self, entry: LogEntry):
        """Queues a log entry to be processed by the background worker."""
        try:
            self._queue.put_nowait(entry)
        except asyncio.QueueFull:
            logger.warning("Log queue is full. Dropping log entry.")

    def shutdown(self):
        """Signals the worker to shut down and waits for it to finish."""
        logger.info("Shutting down logging client.")
        self._shutdown_event.set()
        if self._worker_task:
            # This is tricky in a sync context like atexit. 
            # In a real async app, you would `await self._worker_task`.
            pass

# Singleton instance
logging_client = AsyncLoggingClient()