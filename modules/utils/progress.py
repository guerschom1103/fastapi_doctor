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
        self._doctor_frames = ("\\(o_o) ", " (o_o)/", "\\(o_o)/", " (o_o) ")

    @contextmanager
    def phase(self, label: str) -> Iterator[None]:
        if not self.enabled:
            yield
            return

        stopped = threading.Event()
        started = time.perf_counter()

        def animate() -> None:
            for frame in itertools.cycle(self._doctor_frames):
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

    def summary(self, score: int, findings: list[dict]) -> None:
        if self.enabled:
            severities = {finding.get("severity", "INFO") for finding in findings}
            if "CRITICAL" in severities or score < 50:
                color, face = "31", "( x_x )"
            elif "HIGH" in severities or score < 80:
                color, face = "33", "( o_o )"
            else:
                color, face = "32", "( ^_^ )"
            actionable = sum(
                finding.get("severity") in {"CRITICAL", "HIGH", "MEDIUM"}
                for finding in findings
            )
            mascot = (
                f"\033[{color}m    .---.\n"
                f"   {face}\n"
                "    /|_|\\\n"
                "     / \\\033[0m\n"
            )
            self.stream.write(mascot)
            self.stream.write(
                f"\033[1mAudit termine\033[0m - score {score}/100, "
                f"{actionable} probleme(s) a examiner, {len(findings)} signalement(s) au total\n"
            )
            self.stream.flush()
