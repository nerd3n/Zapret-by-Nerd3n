"""Build the deterministic, explicitly curated resource for the standalone EXE.

This command needs only Python's standard library and the source distribution;
it neither runs the bundled engine nor reads Git metadata. User-created files
outside packaging/payload-files.txt are never enumerated or included.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tempfile
import zipfile

# Direct invocation from tools/ must import the trusted builder's source tree,
# never arbitrary Python code from a caller-supplied --root staging directory.
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from zapret_ui.windows_service import NATIVE_HASHES

MAX_FILES = 256
MAX_FILE_SIZE = 32 * 1024 * 1024
MAX_TOTAL_SIZE = 128 * 1024 * 1024
MAX_MANIFEST_SIZE = 256 * 1024
MAX_FILE_LIST_SIZE = 64 * 1024
FILE_LIST = "packaging/payload-files.txt"
LICENSE_FILES = frozenset({
    "LICENSE", "THIRD_PARTY.md", "PYTHON-LICENSE.txt", "GSAP-LICENSE.txt",
    "DESKTOP-LICENSES.txt",
})
ACTIVE_DEFAULTS = {
    "bundle/bin/ACTIVE_DISCORD_UDP.bin": "bundle/bin/quic_initial_steamcommunity_com.bin",
    "bundle/bin/ACTIVE_GAME_UDP.bin": "bundle/bin/quic_initial_4pda_to.bin",
}
REQUIRED_FILES = (
    {f"bundle/bin/{name}" for name in NATIVE_HASHES}
    | set(ACTIVE_DEFAULTS) | set(ACTIVE_DEFAULTS.values())
    | {f"licenses/{name}" for name in LICENSE_FILES}
    | {"bundle/general.bat", "bundle/utils/targets.txt", "bundle/LICENSE.txt",
       "profiles/infolink-shchelkovo.json"}
)
_COMPONENT = re.compile(r"[A-Za-z0-9_. ()-]+\Z")
_RESERVED = re.compile(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|\Z)", re.I)
_PRIVATE_PARTS = frozenset({"data", "logs", "test results", "__pycache__", ".git", ".env"})


class PayloadError(ValueError):
    """The staging tree cannot produce a safe release payload."""


def _relative_path(value: str) -> str:
    parts = value.split("/")
    if (not value or any(part in ("", ".", "..") for part in parts)
            or any(not _COMPONENT.fullmatch(part) or part.endswith((".", " "))
                   or _RESERVED.match(part) for part in parts)):
        raise PayloadError(f"Unsafe payload path: {value!r}")
    if (any(part.casefold() in _PRIVATE_PARTS for part in parts)
            or parts[-1].casefold().endswith(("-user.txt", ".log", ".pyc", ".backup", ".test-backup.txt"))
            or parts[-1].casefold() == "game_filter.enabled"):
        raise PayloadError(f"Private/runtime file is forbidden: {value}")
    return str(PurePosixPath(value))


def _plain_path(path: Path, *, allow_missing: bool = False) -> Path:
    path = Path(os.path.abspath(path))
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            if allow_missing:
                continue
            raise PayloadError(f"Missing input: {part}") from None
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PayloadError(f"Links and reparse points are forbidden: {part}")
        if part != path and not stat.S_ISDIR(info.st_mode):
            raise PayloadError(f"Expected a directory: {part}")
    return path


def _read_regular(path: Path, limit: int) -> bytes:
    path = _plain_path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise PayloadError(f"Expected a regular file without hard links: {path}")
    if before.st_size > limit:
        raise PayloadError(f"Input exceeds size limit: {path.name}")
    with path.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        content = stream.read(limit + 1)
        finished = os.fstat(stream.fileno())
    after = _plain_path(path).lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    if (len(content) > limit or len(content) != before.st_size
            or any(identity(info) != identity(before) for info in (opened, finished, after))):
        raise PayloadError(f"Input changed during the build: {path.name}")
    return content


def load_file_list(root: Path) -> list[tuple[str, str]]:
    """Read source/destination pairs; reject aliases and unexpected remappings."""
    root = _plain_path(root)
    try:
        contents = _read_regular(root / FILE_LIST, MAX_FILE_LIST_SIZE).decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PayloadError("The payload file list must be UTF-8") from exc
    result = []
    sources: set[str] = set()
    destinations: set[str] = set()
    for line in contents.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(" => ")
        if len(fields) not in (1, 2):
            raise PayloadError(f"Invalid file-list line: {line!r}")
        source = _relative_path(fields[0])
        destination = _relative_path(fields[-1])
        expected = f"licenses/{source}" if source in LICENSE_FILES else source
        if destination != expected or not destination.startswith(("bundle/", "profiles/", "licenses/")):
            raise PayloadError(f"Unexpected payload mapping: {line}")
        if destination.startswith("licenses/") and source not in LICENSE_FILES:
            raise PayloadError(f"Unknown license input: {source}")
        if source.casefold() in sources or destination.casefold() in destinations:
            raise PayloadError(f"Duplicate/case alias in payload list: {line}")
        sources.add(source.casefold())
        destinations.add(destination.casefold())
        result.append((source, destination))
    if not 1 <= len(result) <= MAX_FILES:
        raise PayloadError("Invalid number of payload files")
    missing = REQUIRED_FILES - {destination for _, destination in result}
    if missing:
        raise PayloadError(f"Required payload files absent from list: {', '.join(sorted(missing))}")
    return sorted(result, key=lambda pair: pair[1])


def _entry(path: str) -> zipfile.ZipInfo:
    entry = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    entry.create_system = 3
    entry.external_attr = (stat.S_IFREG | 0o644) << 16
    # The outer PyInstaller package compresses this resource. Stored ZIP entries
    # keep payload bytes deterministic without depending on a zlib version.
    entry.compress_type = zipfile.ZIP_STORED
    return entry


def build_payload(root: Path, output: Path) -> dict:
    """Validate all listed inputs, then atomically write a complete payload ZIP."""
    root = _plain_path(root)
    pairs = load_file_list(root)
    output = _plain_path(output, allow_missing=True)
    if output in {root / source for source, _ in pairs} | {root / FILE_LIST}:
        raise PayloadError("Output must not overwrite a payload input")
    if output.exists() and (not output.is_file() or output.stat().st_nlink != 1):
        raise PayloadError("Output must be a regular file without hard links")
    files: dict[str, bytes] = {}
    rows = []
    total = 0
    for source, destination in pairs:
        content = _read_regular(root / source, MAX_FILE_SIZE)
        total += len(content)
        if total > MAX_TOTAL_SIZE:
            raise PayloadError("Payload exceeds total size limit")
        files[destination] = content
        rows.append({"path": destination, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)})
    for name, expected in NATIVE_HASHES.items():
        if hashlib.sha256(files[f"bundle/bin/{name}"]).hexdigest() != expected:
            raise PayloadError(f"Pinned native component hash mismatch: {name}")
    for active, original in ACTIVE_DEFAULTS.items():
        if files[active] != files[original]:
            raise PayloadError(f"ACTIVE seed differs from canonical default: {active}")
    manifest = {"schema": 1, "files": rows}
    encoded_manifest = (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(encoded_manifest) > MAX_MANIFEST_SIZE:
        raise PayloadError("Payload manifest exceeds size limit")

    output.parent.mkdir(parents=True, exist_ok=True)
    _plain_path(output.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".payload-", suffix=".zip", dir=output.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            with zipfile.ZipFile(stream, "w", allowZip64=False) as archive:
                archive.writestr(_entry("manifest.json"), encoded_manifest)
                for name, content in files.items():
                    archive.writestr(_entry(name), content)
        with zipfile.ZipFile(temporary) as archive:
            if archive.testzip() is not None:
                raise PayloadError("Generated payload failed its ZIP CRC check")
        os.replace(temporary, output)
    finally:
        if temporary.exists():
            temporary.unlink()
    return {"files": len(rows), "bytes": total, "sha256": hashlib.sha256(output.read_bytes()).hexdigest()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="Source/staging root with packaging/payload-files.txt")
    parser.add_argument("--output", type=Path, required=True, help="Destination payload.zip")
    options = parser.parse_args(argv)
    try:
        result = build_payload(options.root, options.output)
    except (OSError, PayloadError, zipfile.BadZipFile) as exc:
        print(f"Payload build failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
