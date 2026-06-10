"""Background fetch job for refreshing inventory data on disk.

Runs ``femur`` in a subprocess and reloads the
:class:`~.store.InventoryStore` on success.
"""

import logging
import subprocess
import sys
import threading
import time
from typing import Optional

from .store import InventoryStore

log = logging.getLogger("femur.server")


class FetchJob:
    """Runs ``femur`` in a subprocess to refresh data on disk."""

    def __init__(
        self,
        data_dir: str,
        env_file: Optional[str] = None,
        extra_args: Optional[list[str]] = None,
    ) -> None:
        self.data_dir = data_dir
        self.env_file = env_file
        self.extra_args = extra_args or []
        self._running = False
        self._lock = threading.Lock()
        self._last_run: Optional[float] = None
        self._last_error: Optional[str] = None

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def last_error(self) -> Optional[str]:
        return self._last_error

    def trigger(self, store: InventoryStore) -> bool:
        """Start a background fetch.  Returns ``False`` if already running."""
        with self._lock:
            if self._running:
                return False
            self._running = True

        def _run() -> None:
            try:
                cmd = [
                    sys.executable,
                    "-m",
                    "femur_cli",
                    "--output-format",
                    "jsonl",
                    "--output-dir",
                    self.data_dir,
                ]
                if self.env_file:
                    cmd.extend(["--env-file", self.env_file])
                cmd.extend(self.extra_args)
                log.info("Starting fetch job: %s", " ".join(cmd))
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=7200,
                )
                if result.returncode != 0:
                    self._last_error = result.stderr[:500]
                    log.error("Fetch job failed: %s", self._last_error)
                else:
                    self._last_error = None
                    store.load()
                    log.info("Fetch job completed, store reloaded")
            except Exception as exc:
                self._last_error = str(exc)
                log.error("Fetch job error: %s", exc)
            finally:
                with self._lock:
                    self._running = False
                    self._last_run = time.time()

        threading.Thread(target=_run, daemon=True).start()
        return True
