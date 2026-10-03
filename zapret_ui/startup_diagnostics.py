"""Bounded output from one engine process and a durable last-failure record."""
from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import threading


MAX_OUTPUT_BYTES = 16 * 1024
MESSAGE_OUTPUT_CHARS = 3000
READER_WAIT_SECONDS = 1.0
FAILURE_FILENAME = "last-startup-failure.json"


class StartupOutput:
    def __init__(self, stream, log):
        self.stream = stream
        self.log = log
        self.lock = threading.Lock()
        self.tail = bytearray()
        self.truncated = False
        self.reader_error = None
        self.complete = threading.Event()
        self.reader = threading.Thread(target=self._read, name="winws-output", daemon=True)

    def start(self):
        self.reader.start()

    def _read(self):
        try:
            while True:
                chunk = self.stream.readline(MAX_OUTPUT_BYTES)
                if not chunk:
                    break
                with self.lock:
                    self.tail.extend(chunk)
                    if len(self.tail) > MAX_OUTPUT_BYTES:
                        del self.tail[:-MAX_OUTPUT_BYTES]
                        self.truncated = True
                # Display logging is independent of capture: a broken logger must
                # neither lose the diagnostic tail nor stop draining the child pipe.
                try:
                    self.log("engine", chunk.decode("utf-8", errors="replace").strip())
                except Exception:
                    pass
        except Exception as exc:
            with self.lock:
                self.reader_error = str(exc)[:1000]
        finally:
            try:
                self.stream.close()
            except Exception as exc:
                with self.lock:
                    self.reader_error = self.reader_error or str(exc)[:1000]
            self.complete.set()

    def wait(self):
        # Descendants can inherit stdout and keep it open after the engine exits.
        # Never block the UI indefinitely or close a pipe another thread is reading.
        self.reader.join(READER_WAIT_SECONDS)
        with self.lock:
            return {"outputTail": bytes(self.tail).decode("utf-8", errors="replace").strip(),
                    "outputTruncated": self.truncated,
                    "readerComplete": self.complete.is_set(), "readerError": self.reader_error}


def save_failure(data_directory: Path, record: dict) -> Path:
    """Replace only the last diagnostic, keeping the previous record on write failure."""
    destination = data_directory / FAILURE_FILENAME
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=data_directory,
                                         prefix=".startup-failure-", suffix=".tmp", delete=False) as output:
            temporary = Path(output.name)
            json.dump(record, output, ensure_ascii=False, indent=2)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        return destination
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass  # Cleanup failure cannot replace the original diagnostic failure.
