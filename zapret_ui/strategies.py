"""Read Flowseal launch arguments as data; never invoke a batch file or a shell.

The deliberately small grammar targets the pinned Flowseal revision. A future
upstream option requires a code review rather than silently broadening execution.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

UPSTREAM_URL = "https://github.com/Flowseal/zapret-discord-youtube"
UPSTREAM_COMMIT = "eb16c1419057e36b8a36fbe7c959483450e6ac8b"
PARAMETERS_URL = "https://github.com/bol-van/zapret/blob/master/docs/readme.md#nfqws"
MAX_BATCH_BYTES = 256 * 1024
MAX_ASSET_BYTES = 32 * 1024 * 1024
MAX_ARGUMENTS = 1024
MAX_COMMAND_CHARS = 30000
GAME_PORTS = "12"  # service.bat: load_game_filter, disabled mode.

_USER_DEFAULTS = {
    "ipset-exclude-user.txt": b"203.0.113.113/32\r\n",
    "list-general-user.txt": b"# Never leave this file empty\r\ndomain.example.abc\r\n",
    "list-exclude-user.txt": b"domain.example.abc\r\n",
}
# The two checked-in ACTIVE files match these assets byte-for-byte at the pin.
_ACTIVE_DEFAULTS = {
    "ACTIVE_DISCORD_UDP.bin": "quic_initial_steamcommunity_com.bin",
    "ACTIVE_GAME_UDP.bin": "quic_initial_4pda_to.bin",
}
_LIST_OPTIONS = {"--hostlist", "--hostlist-exclude", "--ipset", "--ipset-exclude"}
_BINARY_OPTIONS = {
    "--dpi-desync-fake-discord", "--dpi-desync-fake-http",
    "--dpi-desync-fake-quic", "--dpi-desync-fake-stun",
    "--dpi-desync-fake-tls", "--dpi-desync-fake-unknown",
    "--dpi-desync-fake-unknown-udp", "--dpi-desync-fakedsplit-pattern",
    "--dpi-desync-split-seqovl-pattern",
}
_PORT_OPTIONS = {"--wf-tcp", "--wf-udp", "--filter-tcp", "--filter-udp"}
_ENUM_OPTIONS = {
    "--dpi-desync": {"fake", "fakedsplit", "multisplit", "multidisorder", "hostfakesplit", "syndata"},
    "--dpi-desync-fooling": {"none", "ts", "badseq", "md5sig"},
    "--filter-l3": {"ipv4", "ipv6"},
    "--filter-l7": {"discord", "stun", "unknown", "quic", "http", "tls"},
    "--ip-id": {"zero", "seq", "seqgroup", "rnd"},
    "--dpi-desync-any-protocol": {"0", "1"},
}
_SINGLE_ENUM_OPTIONS = {"--ip-id", "--dpi-desync-any-protocol"}
_SCALAR_OPTIONS = {
    "--dpi-desync-repeats", "--dpi-desync-split-pos",
    "--dpi-desync-split-seqovl", "--dpi-desync-cutoff",
    "--dpi-desync-badseq-increment", "--dpi-desync-fake-tls-mod",
    "--dpi-desync-hostfakesplit-mod", "--hostlist-domains",
    "--hostlist-exclude-domains",
}
_ALLOWED_OPTIONS = _LIST_OPTIONS | _BINARY_OPTIONS | _PORT_OPTIONS | set(_ENUM_OPTIONS) | _SCALAR_OPTIONS
_START = re.compile(r'^start\s+"[^"\r\n]*"\s+/min\s+"%BIN%winws\.exe"\s+(.+)$', re.I)
_FILENAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_. -]{0,127}\Z")
_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9-]{2,63}\Z")


class StrategyError(ValueError):
    """The bundle or strategy is outside the supported, bounded data format."""


def _root(bundle_path: Path) -> Path:
    try:
        root = Path(bundle_path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise StrategyError(f"Папка zapret недоступна: {bundle_path}") from exc
    if not root.is_dir():
        raise StrategyError("Укажите папку распакованного zapret.")
    return root


def _inside(root: Path, path: Path, *, exists: bool = True) -> Path:
    try:
        resolved = path.resolve(strict=exists)
        resolved.relative_to(root)
    except (OSError, ValueError, RuntimeError) as exc:
        raise StrategyError(f"Путь должен находиться внутри папки zapret: {path.name}") from exc
    return resolved


def _file(root: Path, path: Path, *, limit: int = MAX_ASSET_BYTES, allow_empty: bool = False) -> Path:
    resolved = _inside(root, path)
    if not resolved.is_file():
        raise StrategyError(f"Не найден файл: {path.name}")
    size = resolved.stat().st_size
    if size > limit or (not allow_empty and size == 0):
        raise StrategyError(f"Недопустимый размер файла: {path.name}")
    return resolved


def prepare_bundle(bundle_path: Path) -> list[str]:
    """Create missing upstream defaults only; return their relative filenames.

    Existing user lists and fake payload choices are preserved. This function
    never changes service settings, game-filter settings or the user's ipset.
    """
    root = _root(bundle_path)
    for dirname in ("bin", "lists"):
        directory = _inside(root, root / dirname)
        if not directory.is_dir():
            raise StrategyError(f"Не найдена папка: {dirname}")
    exe = _file(root, root / "bin" / "winws.exe")
    with exe.open("rb") as stream:
        if stream.read(2) != b"MZ":
            raise StrategyError("bin/winws.exe не похож на исполняемый файл Windows.")
    created = []
    defaults = [("lists", name, content) for name, content in _USER_DEFAULTS.items()]
    for name, source in _ACTIVE_DEFAULTS.items():
        target = _inside(root, root / "bin" / name, exists=False)
        if not target.exists():
            defaults.append(("bin", name, _file(root, root / "bin" / source).read_bytes()))
    for dirname, name, content in defaults:
        target = _inside(root, root / dirname / name, exists=False)
        if target.exists():
            _file(root, target, allow_empty=dirname == "lists")
            continue
        try:
            with target.open("xb") as stream:
                stream.write(content)
        except FileExistsError:
            _file(root, target, allow_empty=dirname == "lists")
        else:
            created.append(f"{dirname}/{name}")
    return created


def _logical_lines(text: str) -> list[str]:
    pending = ""
    lines = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if line.endswith("^"):
            pending += line[:-1] + " "
            continue
        lines.append(pending + line)
        pending = ""
    if pending:
        raise StrategyError("Незавершённый перенос строки в стратегии.")
    return lines


def _tokens(command: str) -> list[str]:
    """Tokenize only the batch argument subset used by the pinned strategies."""
    command = command.replace("^!", "!")
    if any(char in command for char in "&|<>^`\x00\r\n"):
        raise StrategyError("Управляющие операторы командной строки запрещены.")
    result, token = [], []
    quoted = False
    for char in command:
        if char == '"':
            quoted = not quoted
        elif char.isspace() and not quoted:
            if token:
                result.append("".join(token))
                token = []
        else:
            token.append(char)
    if quoted:
        raise StrategyError("Незакрытая кавычка в стратегии.")
    if token:
        result.append("".join(token))
    if not result or len(result) > MAX_ARGUMENTS:
        raise StrategyError("Недопустимое количество аргументов стратегии.")
    return result


def _asset(root: Path, value: str, dirname: str) -> str:
    prefix = "%LISTS%" if dirname == "lists" else "%BIN%"
    if not value.upper().startswith(prefix):
        raise StrategyError("Файлы стратегии должны быть заданы через %BIN% или %LISTS%.")
    name = value[len(prefix):]
    if not _FILENAME.fullmatch(name) or ".." in name or name.endswith((" ", ".")):
        raise StrategyError(f"Недопустимое имя файла: {name}")
    expected_suffix = ".txt" if dirname == "lists" else ".bin"
    if not name.lower().endswith(expected_suffix):
        raise StrategyError(f"Недопустимый тип файла: {name}")
    return str(_file(root, root / dirname / name, allow_empty=dirname == "lists"))


def _valid_scalar(option: str, value: str) -> bool:
    if option in {"--hostlist-domains", "--hostlist-exclude-domains"}:
        return all(_DOMAIN.fullmatch(item) for item in value.split(","))
    if option == "--dpi-desync-repeats":
        return bool(re.fullmatch(r"[1-9][0-9]?", value)) and int(value) <= 32
    if option == "--dpi-desync-split-seqovl":
        return bool(re.fullmatch(r"[1-9][0-9]{0,4}", value)) and int(value) <= 65535
    if option == "--dpi-desync-badseq-increment":
        return bool(re.fullmatch(r"-?[0-9]{1,10}", value)) and -(2**31) <= int(value) < 2**31
    if option == "--dpi-desync-cutoff":
        return bool(re.fullmatch(r"[nds]?[1-9][0-9]{0,3}", value))
    if option == "--dpi-desync-split-pos":
        marker = r"(?:[1-9][0-9]{0,3}|(?:midsld|host|sniext|method)(?:[+-][1-9][0-9]{0,3})?)"
        return bool(re.fullmatch(marker + r"(?:," + marker + r"){0,15}", value))
    if option == "--dpi-desync-fake-tls-mod":
        return all(item in {"none", "rnd", "dupsid", "rndsni", "padencap"} or
                   (item.startswith("sni=") and _DOMAIN.fullmatch(item[4:]))
                   for item in value.split(","))
    if option == "--dpi-desync-hostfakesplit-mod":
        return all(item in {"none", "altorder=0", "altorder=1"} or
                   (item.startswith("host=") and _DOMAIN.fullmatch(item[5:]))
                   for item in value.split(","))
    return False


def _argument(root: Path, token: str) -> str:
    if token == "--new":
        return token
    option, separator, value = token.partition("=")
    if not separator or option not in _ALLOWED_OPTIONS or not value or len(value) > 4096:
        raise StrategyError(f"Неподдерживаемый аргумент: {option}")
    if option in _LIST_OPTIONS:
        return option + "=" + _asset(root, value, "lists")
    if option in _BINARY_OPTIONS:
        if value == "!" and option == "--dpi-desync-fake-tls":
            return token
        if re.fullmatch(r"0x(?:[0-9a-fA-F]{2}){1,2048}", value):
            return token
        return option + "=" + _asset(root, value, "bin")
    value = re.sub(r"%GameFilter(?:TCP|UDP)%", GAME_PORTS, value, flags=re.I)
    if "%" in value or "!" in value:
        raise StrategyError(f"Неизвестная переменная в аргументе: {option}")
    if option in _PORT_OPTIONS:
        valid = True
        for item in value.split(","):
            if not re.fullmatch(r"[1-9][0-9]{0,4}(?:-[1-9][0-9]{0,4})?", item):
                valid = False
                break
            ports = [int(port) for port in item.split("-")]
            if any(port > 65535 for port in ports) or ports[0] > ports[-1]:
                valid = False
                break
    elif option in _SINGLE_ENUM_OPTIONS:
        valid = value in _ENUM_OPTIONS[option]
    elif option in _ENUM_OPTIONS:
        valid = all(item in _ENUM_OPTIONS[option] for item in value.split(","))
    else:
        valid = _valid_scalar(option, value)
    if not valid:
        raise StrategyError(f"Недопустимое значение {option}: {value}")
    return option + "=" + value


def parse_strategy(batch_path: Path, bundle_path: Path) -> list[str]:
    """Return complete subprocess argv; ignore batch preamble without running it."""
    root = _root(bundle_path)
    batch = _file(root, Path(batch_path), limit=MAX_BATCH_BYTES)
    try:
        text = batch.read_text(encoding="utf-8-sig")
    except UnicodeError as exc:
        raise StrategyError(f"Стратегия должна быть в UTF-8: {batch.name}") from exc
    starts = [line.strip() for line in _logical_lines(text) if re.match(r"\s*start\b", line, re.I)]
    if len(starts) != 1 or not (match := _START.fullmatch(starts[0])):
        raise StrategyError(f"Ожидалась одна команда запуска bin/winws.exe: {batch.name}")
    argv = [str(_file(root, root / "bin" / "winws.exe"))]
    argv.extend(_argument(root, token) for token in _tokens(match.group(1)))
    if not any(arg.startswith("--wf-tcp=") for arg in argv) or not any(arg.startswith("--wf-udp=") for arg in argv):
        raise StrategyError("В стратегии отсутствуют ограничения TCP/UDP перехвата.")
    if not any(arg.startswith("--dpi-desync=") for arg in argv):
        raise StrategyError("В стратегии отсутствуют параметры dpi-desync.")
    # A conservative allowance for quoting and UTF-16 Windows command lines.
    if sum(len(arg.encode("utf-16-le")) // 2 + 3 for arg in argv) > MAX_COMMAND_CHARS:
        raise StrategyError("Командная строка стратегии слишком длинная.")
    return argv


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _variants(stock: list[dict]) -> list[dict]:
    by_source = {item["source"]: item for item in stock}
    specs = [
        ("general.bat", "split-pos", "2"),
        ("general.bat", "split-pos", "3"),
        ("general (ALT11).bat", "repeats", "4"),
        ("general (ALT11).bat", "repeats", "12"),
        ("general (FAKE TLS AUTO).bat", "repeats", "6"),
        ("general (FAKE TLS AUTO).bat", "repeats", "8"),
    ]
    result = []
    for source, parameter, value in specs:
        base = by_source.get(source)
        if base is None:
            continue
        prefix = "--dpi-desync-" + parameter + "="
        argv = [prefix + value if arg.startswith(prefix) else arg for arg in base["argv"]]
        if argv == base["argv"]:
            continue
        result.append({
            "id": f"experiment-{_slug(Path(source).stem)}-{parameter}-{value}",
            "name": f"EXP · {base['name']} · {parameter} {value}",
            "family": base["family"],
            "experimental": True,
            "description": f"Эксперимент: {prefix}{value} во всех подходящих профилях. Эффективность на вашем провайдере ещё не проверена.",
            "source": source,
            "source_sha256": base["source_sha256"],
            "base_id": base["id"],
            "changes": [{"parameter": prefix[:-1], "value": value}],
            "argv": argv,
        })
    return result


def catalog(bundle_path: Path) -> list[dict]:
    """Return validated stock strategies followed by six controlled experiments."""
    root = _root(bundle_path)
    prepare_bundle(root)
    batches = sorted(root.glob("general*.bat"), key=lambda p: (p.name != "general.bat", p.name.casefold()))
    if not batches or len(batches) > 128:
        raise StrategyError("В папке должны быть файлы general*.bat (не более 128).")
    stock, seen = [], set()
    for batch in batches:
        if not re.fullmatch(r"general(?: \([A-Za-z0-9 ]+\))?\.bat", batch.name):
            raise StrategyError(f"Неподдерживаемое имя стратегии: {batch.name}")
        ident = "stock-" + _slug(batch.stem)
        if ident in seen:
            raise StrategyError("Имена стратегий создают одинаковые идентификаторы.")
        seen.add(ident)
        argv = parse_strategy(batch, root)
        name = batch.stem.removeprefix("general").strip(" ()") or "GENERAL"
        family = "FAKE TLS AUTO" if "FAKE TLS AUTO" in name else "SIMPLE FAKE" if "SIMPLE FAKE" in name else "ALT" if name.startswith("ALT") else name
        stock.append({
            "id": ident, "name": name, "family": family,
            "experimental": name == "EXP",
            "description": "Стратегия Flowseal. Работоспособность зависит от сети; требуется локальная проверка.",
            "source": batch.name,
            "source_sha256": hashlib.sha256(batch.read_bytes()).hexdigest(),
            "argv": argv,
        })
    return stock + _variants(stock)


def describe_provenance(bundle_path: Path | None = None) -> dict:
    """Machine-readable provenance without claiming an imported bundle is trusted."""
    result = {
        "upstream": UPSTREAM_URL,
        "compatible_commit": UPSTREAM_COMMIT,
        "parameters": PARAMETERS_URL,
        "game_filter": "disabled",
        "game_tcp_ports": GAME_PORTS,
        "game_udp_ports": GAME_PORTS,
        "experimental_variants": 6,
        "experimental_status": "not_verified_on_provider",
        "batch_execution": False,
        "user_defaults_source": f"{UPSTREAM_URL}/blob/{UPSTREAM_COMMIT}/service.bat",
        "active_defaults": dict(_ACTIVE_DEFAULTS),
        "note": "Совместимая ревизия не удостоверяет подлинность произвольной выбранной папки.",
    }
    if bundle_path is not None:
        root = _root(bundle_path)
        result["bundle_path"] = str(root)
        exe = _file(root, root / "bin" / "winws.exe")
        result["winws_sha256"] = hashlib.sha256(exe.read_bytes()).hexdigest()
    return result
