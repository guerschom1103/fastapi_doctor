"""Small, dependency-free terminal progress display."""
from __future__ import annotations

import itertools
import sys
import threading
import time
from contextlib import contextmanager
from typing import Iterator, TextIO


class ProgressUI:
    """Render animated audit phases without contaminating machine-readable stdout."""

    def __init__(self, mode: str = "auto", stream: TextIO = sys.stderr) -> None:
        self.stream = stream
        self.enabled = mode == "always" or (mode == "auto" and stream.isatty())
        self._lock = threading.Lock()
        encoding = getattr(stream, "encoding", None) or "utf-8"
        try:
            "\u280b\u2713\u2717".encode(encoding)
            self._frames = (
                "\u280b", "\u2819", "\u2839", "\u2838", "\u283c",
                "\u2834", "\u2826", "\u2827", "\u2807", "\u280f",
            )
            self._ok, self._error = "\u2713", "\u2717"
        except (LookupError, UnicodeEncodeError):
            self._frames = ("|", "/", "-", "\\")
            self._ok, self._error = "+", "x"

    @contextmanager
    def phase(self, label: str) -> Iterator[None]:
        if not self.enabled:
            yield
            return

        stopped = threading.Event()
        started = time.perf_counter()

        def animate() -> None:
            for frame in itertools.cycle(self._frames):
                if stopped.is_set():
                    break
                with self._lock:
                    self.stream.write(f"\r\033[36m{frame}\033[0m  {label}...")
                    self.stream.flush()
                stopped.wait(0.08)

        worker = threading.Thread(target=animate, daemon=True)
        worker.start()
        try:
            yield
        except Exception:
            stopped.set()
            worker.join()
            with self._lock:
                self.stream.write(f"\r\033[31m{self._error}\033[0m  {label}\033[K\n")
                self.stream.flush()
            raise
        else:
            stopped.set()
            worker.join()
            elapsed = time.perf_counter() - started
            with self._lock:
                self.stream.write(f"\r\033[32m{self._ok}\033[0m  {label} \033[2m{elapsed:.2f}s\033[0m\033[K\n")
                self.stream.flush()

    def summary(self, score: int, finding_count: int) -> None:
        if self.enabled:
            self.stream.write(
                f"\033[1mAudit termine\033[0m - score {score}/100, "
                f"{finding_count} probleme(s) detecte(s)\n"
            )
            self.stream.flush()
