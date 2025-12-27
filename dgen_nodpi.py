import argparse
import asyncio
import json
import logging
import os
import random
import re
import socket
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    # Windows only (autostart registry). Keep import optional for portability.
    import winreg  # type: ignore
except Exception:  # pragma: no cover
    winreg = None  # type: ignore


VERSION = "4.0.0-alpha"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(SCRIPT_DIR, "dgen-nodpi4.json")
DEFAULT_LOG_PATH = os.path.join(SCRIPT_DIR, "dgen-nodpi4.log")

DEFAULT_PROXY_HOST = "127.0.0.1"
DEFAULT_PROXY_PORT = 8881
DEFAULT_PAC_PORT = 8882

AUTOSTART_REG_NAME = "DGenNoDPI4"
AUTOSTART_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


DGEN_BANNER = r"""
██████╗░  ░██████╗░███████╗███╗░░██╗
██╔══██╗  ██╔════╝░██╔════╝████╗░██║
██║░░██║  ██║░░██╗░█████╗░░██╔██╗██║
██║░░██║  ██║░░╚██╗██╔══╝░░██║╚████║
██████╔╝  ╚██████╔╝███████╗██║░╚███║
╚═════╝░  ░╚═════╝░╚══════╝╚═╝░░╚══╝

D-Gen NoDPI
""".rstrip("\n")


def banner() -> str:
    return f"{DGEN_BANNER}\nVersion: {VERSION}"


def _now_ms() -> int:
    return int(time.time() * 1000)


def _asyncio_exception_handler(loop: asyncio.AbstractEventLoop, context: Dict[str, Any]) -> None:
    """Make asyncio on Windows less noisy.

    On Windows (Proactor loop), it's common to see noisy tracebacks like:
      Exception in callback ... ConnectionResetError: [WinError 10054]
    when a peer resets a socket. This isn't actionable for our proxy.
    """
    exc = context.get("exception")
    if isinstance(exc, ConnectionResetError):
        return
    if isinstance(exc, OSError) and getattr(exc, "winerror", None) == 10054:
        return
    loop.default_exception_handler(context)


def _eprint(*args: object) -> None:
    print(*args, file=sys.stderr)


def setup_logging(path: str, verbose: bool) -> logging.Logger:
    logger = logging.getLogger("dgen_nodpi4")
    for h in list(logger.handlers):
        logger.removeHandler(h)
    logger.propagate = False

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Console logging policy:
    # - default (verbose=False): keep console quiet (WARN+). We'll show live stats separately.
    # - verbose=True: show INFO/DEBUG in console.
    sh = logging.StreamHandler(stream=sys.stderr)
    sh.setLevel(logging.DEBUG if verbose else logging.WARNING)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    fh = logging.FileHandler(path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger


@dataclass
class FragmentConfig:
    enabled: bool = True
    # How many parts to split the first ClientHello record into.
    # (If too high, it may hurt performance.)
    min_parts: int = 2
    max_parts: int = 6
    # Strategy for splitting the first ClientHello record.
    # - random_parts: N parts with random sizes
    # - fixed_parts: exactly fixed_parts parts with random sizes
    # - chunk_size: fixed-size chunks (best-effort)
    # - tiny_first: a tiny first record then the rest
    # - sni_cut: try to cut inside/near SNI bytes then split remainder
    strategy: str = "random_parts"
    fixed_parts: int = 4
    chunk_size: int = 1200
    tiny_first_min: int = 1
    tiny_first_max: int = 5
    sni_cut_pad: int = 2
    # Optional timing jitter between writes (milliseconds). 0 disables.
    jitter_ms_min: int = 0
    jitter_ms_max: int = 0
    # Hard cap on payload size for fragmentation to avoid pathological behavior.
    max_payload: int = 4096


@dataclass
class UpstreamConfig:
    # When enabled, CONNECT tunnels are established via an upstream HTTP proxy.
    # This is the simplest "remote-node" baseline: run the same tool on a remote box,
    # then point local D-Gen to that upstream.
    enabled: bool = False
    host: str = ""
    port: int = 0


@dataclass
class ConsoleConfig:
    # Console output mode when verbose=False.
    # - quiet: no live stats line
    # - stats: show a single updating stats line
    mode: str = "stats"


@dataclass
class Rule:
    suffix: str
    action: str  # "pass" | "fragment"
    tls: Optional[Dict[str, Any]] = None


@dataclass
class Config:
    proxy_host: str
    proxy_port: int
    pac_port: int

    log_path: str

    verbose: bool
    fragment: FragmentConfig

    prefer_ipv4: bool
    dial_timeout_s: float

    upstream: UpstreamConfig

    console: ConsoleConfig

    # Domain matching mode for rule suffixes.
    # - strict: match exact host or dot-boundary suffix (example.com or *.example.com)
    # - loose : match any suffix (also matches not-example.com if it endswith example.com)
    domain_matching: str

    rules: List[Rule]


@dataclass
class Metrics:
    connections_total: int = 0
    connections_active: int = 0

    connect_tunnels: int = 0
    http_requests: int = 0

    tls_clienthello_seen: int = 0
    tls_fragmented: int = 0


def _fmt_stats(m: Metrics) -> str:
    frag_pct = 0.0
    if m.tls_clienthello_seen:
        frag_pct = (m.tls_fragmented / max(1, m.tls_clienthello_seen)) * 100.0
    return (
        f"Conn: active={m.connections_active} total={m.connections_total} | "
        f"HTTP={m.http_requests} CONNECT={m.connect_tunnels} | "
        f"TLS_hello={m.tls_clienthello_seen} frag={m.tls_fragmented} ({frag_pct:.0f}%)"
    )


async def _stats_loop(m: Metrics) -> None:
    # Keep printing a single updating line. Works well in cmd/powershell.
    try:
        while True:
            line = _fmt_stats(m)
            # pad to clear remnants of previous line
            print("\r" + line.ljust(120), end="", flush=True)
            await asyncio.sleep(1.0)
    except asyncio.CancelledError:
        # Newline so the prompt doesn't stick to the stats line
        print()
        raise


def default_config() -> Dict[str, Any]:
    return {
        "proxy": {"host": DEFAULT_PROXY_HOST, "port": DEFAULT_PROXY_PORT},
        "pac": {"port": DEFAULT_PAC_PORT},
        "log": {"path": DEFAULT_LOG_PATH},
        "verbose": False,
        "console": {"mode": "stats"},
        "domains": {"matching": "strict"},
        "net": {
            "prefer_ipv4": True,
            "dial_timeout_s": 6.0,
        },
        "upstream": {
            "enabled": False,
            "host": "",
            "port": 0,
        },
        "fragment": {
            "enabled": True,
            "min_parts": 2,
            "max_parts": 6,
            "strategy": "random_parts",
            "fixed_parts": 4,
            "chunk_size": 1200,
            "tiny_first_min": 1,
            "tiny_first_max": 5,
            "sni_cut_pad": 2,
            "jitter_ms_min": 0,
            "jitter_ms_max": 0,
            "max_payload": 4096,
        },
        "rules": [],
    }


YOUTUBE_RULES: List[Dict[str, Any]] = [
    {
        "suffix": ".youtube.com",
        "action": "fragment",
        "tls": {"fragment": {"strategy": "sni_cut", "jitter_ms_min": 1, "jitter_ms_max": 6}},
    },
    {
        "suffix": "youtu.be",
        "action": "fragment",
        "tls": {"fragment": {"strategy": "sni_cut", "jitter_ms_min": 1, "jitter_ms_max": 6}},
    },
    {
        "suffix": ".googlevideo.com",
        "action": "fragment",
        "tls": {"fragment": {"strategy": "sni_cut", "jitter_ms_min": 1, "jitter_ms_max": 6}},
    },
    {
        "suffix": ".ytimg.com",
        "action": "fragment",
        "tls": {"fragment": {"strategy": "sni_cut", "jitter_ms_min": 1, "jitter_ms_max": 6}},
    },
    {
        "suffix": ".youtubei.googleapis.com",
        "action": "fragment",
        "tls": {"fragment": {"strategy": "sni_cut", "jitter_ms_min": 1, "jitter_ms_max": 6}},
    },
    # Some clients hit these during playback/CDN flows.
    {
        "suffix": ".googleusercontent.com",
        "action": "fragment",
        "tls": {"fragment": {"strategy": "sni_cut", "jitter_ms_min": 1, "jitter_ms_max": 6}},
    },
]


def save_raw_config(path: str, raw: Dict[str, Any]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(raw, f, ensure_ascii=False, indent=2)


def load_config(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        data = default_config()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return data

    # PowerShell's `Set-Content -Encoding UTF8` commonly writes a UTF-8 BOM.
    # json.load() will fail on BOM if we read as plain utf-8.
    with open(path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def parse_config(raw: Dict[str, Any]) -> Config:
    proxy = raw.get("proxy") or {}
    pac = raw.get("pac") or {}
    log = raw.get("log") or {}
    console = raw.get("console") or {}
    domains = raw.get("domains") or {}
    net = raw.get("net") or {}
    upstream = raw.get("upstream") or {}
    frag = raw.get("fragment") or {}

    if not isinstance(console, dict):
        console = {}
    console_mode = str(console.get("mode") or "quiet").strip().lower()
    if console_mode not in ("quiet", "stats"):
        console_mode = "quiet"

    if not isinstance(domains, dict):
        domains = {}
    domain_matching = str(domains.get("matching") or raw.get("domain_matching") or "strict").strip().lower()
    if domain_matching not in ("strict", "loose"):
        domain_matching = "strict"

    rules_raw = raw.get("rules") or []
    rules: List[Rule] = []
    for r in rules_raw:
        if not isinstance(r, dict):
            continue
        suffix = r.get("suffix")
        action = r.get("action")
        tls = r.get("tls")
        if not isinstance(tls, dict):
            tls = None
        if isinstance(suffix, str) and isinstance(action, str):
            rules.append(Rule(suffix=suffix.lower(), action=action.lower(), tls=tls))

    return Config(
        proxy_host=str(proxy.get("host") or DEFAULT_PROXY_HOST),
        proxy_port=int(proxy.get("port") or DEFAULT_PROXY_PORT),
        pac_port=int(pac.get("port") or DEFAULT_PAC_PORT),
        log_path=str(log.get("path") or DEFAULT_LOG_PATH),
        verbose=bool(raw.get("verbose") or False),
        fragment=FragmentConfig(
            enabled=bool(frag.get("enabled") if "enabled" in frag else True),
            min_parts=int(frag.get("min_parts") or 2),
            max_parts=int(frag.get("max_parts") or 6),
            strategy=str(frag.get("strategy") or "random_parts"),
            fixed_parts=int(frag.get("fixed_parts") or 4),
            chunk_size=int(frag.get("chunk_size") or 1200),
            tiny_first_min=int(frag.get("tiny_first_min") or 1),
            tiny_first_max=int(frag.get("tiny_first_max") or 5),
            sni_cut_pad=int(frag.get("sni_cut_pad") or 2),
            jitter_ms_min=int(frag.get("jitter_ms_min") or 0),
            jitter_ms_max=int(frag.get("jitter_ms_max") or 0),
            max_payload=int(frag.get("max_payload") or 4096),
        ),
        rules=rules,

        prefer_ipv4=bool(net.get("prefer_ipv4") if "prefer_ipv4" in net else True),
        dial_timeout_s=float(net.get("dial_timeout_s") if "dial_timeout_s" in net else 6.0),

        upstream=UpstreamConfig(
            enabled=bool(upstream.get("enabled") if "enabled" in upstream else False),
            host=str(upstream.get("host") or ""),
            port=int(upstream.get("port") or 0),
        ),

        console=ConsoleConfig(mode=console_mode),

        domain_matching=domain_matching,
    )


async def dial_direct(cfg: Config, host: str, port: int):
    family = socket.AF_INET if cfg.prefer_ipv4 else 0
    return await asyncio.wait_for(
        asyncio.open_connection(host, port, family=family),
        timeout=cfg.dial_timeout_s,
    )


async def dial(cfg: Config, host: str, port: int):
    # Kept for compatibility with older call sites.
    return await dial_direct(cfg, host, port)


async def upstream_http_connect(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    host: str,
    port: int,
    timeout_s: float,
) -> None:
    req = (
        f"CONNECT {host}:{port} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        "Proxy-Connection: keep-alive\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode("iso-8859-1")
    writer.write(req)
    await writer.drain()

    resp = await read_http_headers(reader, timeout_s=timeout_s)
    first = resp.split(b"\r\n", 1)[0] if resp else b""
    if not first.startswith(b"HTTP/") or b" 200 " not in first:
        raise RuntimeError(f"upstream CONNECT failed: {first!r}")


def _host_matches_suffix(host: str, suffix: str, mode: str) -> bool:
    h = host.lower().strip(".")
    suf = suffix.lower().strip(".")
    if not h or not suf:
        return False
    if h == suf:
        return True
    if mode == "loose":
        return h.endswith(suf)
    return h.endswith("." + suf)


def match_action(host: str, rules: List[Rule], domain_matching: str) -> str:
    for r in rules:
        if _host_matches_suffix(host, r.suffix, domain_matching):
            return r.action
    return "pass"


def match_rule(host: str, rules: List[Rule], domain_matching: str) -> Optional[Rule]:
    for r in rules:
        if _host_matches_suffix(host, r.suffix, domain_matching):
            return r
    return None


def check_port_available(host: str, port: int) -> Tuple[bool, str]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind((host, port))
    except OSError as e:
        return False, str(e)
    finally:
        try:
            s.close()
        except Exception:
            pass
    return True, "ok"


def parse_connect_target(target: str) -> Optional[Tuple[str, int]]:
    target = target.strip()
    if not target:
        return None

    if target.startswith("["):
        end = target.find("]")
        if end == -1:
            return None
        host = target[1:end]
        rest = target[end + 1 :]
        if not rest.startswith(":"):
            return None
        port_str = rest[1:]
    else:
        if ":" not in target:
            return None
        host, port_str = target.rsplit(":", 1)

    try:
        port = int(port_str)
    except ValueError:
        return None

    if not host:
        return None

    return host, port


# --- TLS parsing (ClientHello SNI) ---


def parse_tls_sni_from_client_hello_record(payload: bytes) -> Optional[str]:
    """Best-effort SNI extraction from a TLS ClientHello.

    This intentionally does NOT implement full TLS; it's a focused parser.
    Returns a hostname or None.
    """
    try:
        # Handshake protocol: type(1)=0x01 ClientHello, len(3)
        if len(payload) < 4:
            return None
        if payload[0] != 0x01:
            return None
        hs_len = int.from_bytes(payload[1:4], byteorder="big")
        body = payload[4 : 4 + hs_len]
        if len(body) < 2 + 32 + 1:
            return None

        # client_version(2) + random(32)
        p = 2 + 32

        # session_id
        sid_len = body[p]
        p += 1 + sid_len
        if p + 2 > len(body):
            return None

        # cipher_suites
        cs_len = int.from_bytes(body[p : p + 2], "big")
        p += 2 + cs_len
        if p + 1 > len(body):
            return None

        # compression_methods
        cm_len = body[p]
        p += 1 + cm_len
        if p + 2 > len(body):
            return None

        # extensions
        ext_len = int.from_bytes(body[p : p + 2], "big")
        p += 2
        exts = body[p : p + ext_len]

        q = 0
        while q + 4 <= len(exts):
            etype = int.from_bytes(exts[q : q + 2], "big")
            elen = int.from_bytes(exts[q + 2 : q + 4], "big")
            q += 4
            data = exts[q : q + elen]
            q += elen

            # server_name extension
            if etype != 0x0000:
                continue
            if len(data) < 2:
                continue
            list_len = int.from_bytes(data[0:2], "big")
            lst = data[2 : 2 + list_len]
            r = 0
            while r + 3 <= len(lst):
                name_type = lst[r]
                name_len = int.from_bytes(lst[r + 1 : r + 3], "big")
                r += 3
                name = lst[r : r + name_len]
                r += name_len
                if name_type == 0 and name:
                    # host_name
                    return name.decode("utf-8", errors="ignore")
        return None
    except Exception:
        return None


def parse_tls_sni_range_from_client_hello_record(payload: bytes) -> Optional[Tuple[str, int, int]]:
    """Best-effort extraction of SNI + (start,end) byte offsets inside `payload`.

    Offsets refer to the SNI hostname bytes inside the TLS ClientHello handshake payload.
    Used to implement an SNI-aware split point.
    """
    try:
        if len(payload) < 4:
            return None
        if payload[0] != 0x01:
            return None
        hs_len = int.from_bytes(payload[1:4], byteorder="big")
        body = payload[4 : 4 + hs_len]
        if len(body) < 2 + 32 + 1:
            return None

        p = 2 + 32
        sid_len = body[p]
        p += 1 + sid_len
        if p + 2 > len(body):
            return None

        cs_len = int.from_bytes(body[p : p + 2], "big")
        p += 2 + cs_len
        if p + 1 > len(body):
            return None

        cm_len = body[p]
        p += 1 + cm_len
        if p + 2 > len(body):
            return None

        ext_len = int.from_bytes(body[p : p + 2], "big")
        p += 2
        exts = body[p : p + ext_len]

        q = 0
        while q + 4 <= len(exts):
            etype = int.from_bytes(exts[q : q + 2], "big")
            elen = int.from_bytes(exts[q + 2 : q + 4], "big")
            q += 4
            data = exts[q : q + elen]
            data_start_in_payload = 4 + p + q
            q += elen

            if etype != 0x0000:
                continue
            if len(data) < 2:
                continue
            list_len = int.from_bytes(data[0:2], "big")
            lst = data[2 : 2 + list_len]
            r = 0
            while r + 3 <= len(lst):
                name_type = lst[r]
                name_len = int.from_bytes(lst[r + 1 : r + 3], "big")
                r += 3
                name = lst[r : r + name_len]
                name_start = data_start_in_payload + 2 + r
                name_end = name_start + name_len
                r += name_len
                if name_type == 0 and name:
                    host = name.decode("utf-8", errors="ignore")
                    return host, name_start, name_end
        return None
    except Exception:
        return None


def _effective_fragment_config(cfg_frag: FragmentConfig, rule: Optional[Rule]) -> FragmentConfig:
    if not rule or not rule.tls:
        return cfg_frag
    tls = rule.tls
    frag = tls.get("fragment") if isinstance(tls, dict) else None
    if not isinstance(frag, dict):
        return cfg_frag

    # Only override keys that are present.
    def _ov(key: str, cur: Any) -> Any:
        if key not in frag:
            return cur
        return frag.get(key)

    return FragmentConfig(
        enabled=bool(_ov("enabled", cfg_frag.enabled)),
        min_parts=int(_ov("min_parts", cfg_frag.min_parts) or cfg_frag.min_parts),
        max_parts=int(_ov("max_parts", cfg_frag.max_parts) or cfg_frag.max_parts),
        strategy=str(_ov("strategy", cfg_frag.strategy) or cfg_frag.strategy),
        fixed_parts=int(_ov("fixed_parts", cfg_frag.fixed_parts) or cfg_frag.fixed_parts),
        chunk_size=int(_ov("chunk_size", cfg_frag.chunk_size) or cfg_frag.chunk_size),
        tiny_first_min=int(_ov("tiny_first_min", cfg_frag.tiny_first_min) or cfg_frag.tiny_first_min),
        tiny_first_max=int(_ov("tiny_first_max", cfg_frag.tiny_first_max) or cfg_frag.tiny_first_max),
        sni_cut_pad=int(_ov("sni_cut_pad", cfg_frag.sni_cut_pad) or cfg_frag.sni_cut_pad),
        jitter_ms_min=int(_ov("jitter_ms_min", cfg_frag.jitter_ms_min) or 0),
        jitter_ms_max=int(_ov("jitter_ms_max", cfg_frag.jitter_ms_max) or 0),
        max_payload=int(_ov("max_payload", cfg_frag.max_payload) or cfg_frag.max_payload),
    )


def _random_sizes(total: int, parts_n: int) -> List[int]:
    parts_n = max(2, min(parts_n, 32))
    sizes: List[int] = []
    remaining = total
    for i in range(parts_n - 1):
        max_here = remaining - (parts_n - 1 - i)
        sz = random.randint(1, max_here)
        sizes.append(sz)
        remaining -= sz
    sizes.append(remaining)
    return sizes


def _split_by_sizes(payload: bytes, sizes: List[int]) -> List[bytes]:
    out: List[bytes] = []
    off = 0
    for sz in sizes:
        if sz <= 0:
            continue
        out.append(payload[off : off + sz])
        off += sz
    return [p for p in out if p]


def _build_fragment_slices(
    payload: bytes,
    frag: FragmentConfig,
    sni_range: Optional[Tuple[int, int]],
) -> List[bytes]:
    if len(payload) < 2:
        return [payload]

    strategy = (frag.strategy or "random_parts").strip().lower()

    if strategy == "chunk_size":
        chunk = max(1, int(frag.chunk_size or 1200))
        parts = [payload[i : i + chunk] for i in range(0, len(payload), chunk)]
        if len(parts) < 2:
            return [payload]
        if len(parts) > 32:
            return [payload]
        return parts

    if strategy == "tiny_first":
        mn = max(1, int(frag.tiny_first_min or 1))
        mx = max(mn, int(frag.tiny_first_max or mn))
        first_sz = random.randint(mn, mx)
        if first_sz >= len(payload):
            return [payload]
        return [payload[:first_sz], payload[first_sz:]]

    if strategy == "fixed_parts":
        parts_n = int(frag.fixed_parts or 4)
        if parts_n < 2 or parts_n > 32:
            return [payload]
        return _split_by_sizes(payload, _random_sizes(len(payload), parts_n))

    if strategy == "sni_cut":
        if sni_range and 0 <= sni_range[0] < sni_range[1] <= len(payload):
            start, end = sni_range
            pad = max(0, int(frag.sni_cut_pad or 0))
            lo = max(1, start - pad)
            hi = min(len(payload) - 1, end + pad)
            if lo < hi:
                cut = random.randint(lo, hi)
                head = payload[:cut]
                tail = payload[cut:]

                # Optionally split the tail further to reach a "parts"-like behavior.
                parts_n = random.randint(frag.min_parts, max(frag.min_parts, frag.max_parts))
                parts_n = max(2, min(parts_n, 32))
                if parts_n <= 2 or len(tail) < 2:
                    return [head, tail]
                tail_sizes = _random_sizes(len(tail), parts_n - 1)
                return [head] + _split_by_sizes(tail, tail_sizes)

        # Fallback: random_parts.

    # default: random_parts
    parts_n = random.randint(frag.min_parts, max(frag.min_parts, frag.max_parts))
    parts_n = max(2, min(parts_n, 32))
    return _split_by_sizes(payload, _random_sizes(len(payload), parts_n))


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while not reader.at_eof() and not writer.is_closing():
            chunk = await reader.read(16 * 1024)
            if not chunk:
                break
            writer.write(chunk)
            await writer.drain()
    except Exception:
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def read_http_headers(reader: asyncio.StreamReader, timeout_s: float) -> bytes:
    try:
        return await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout_s)
    except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        return await reader.read(8192)


def _parse_http_request_line(first_line: bytes) -> Optional[Tuple[str, str, str]]:
    try:
        parts = first_line.decode("iso-8859-1", errors="ignore").split()
        if len(parts) < 3:
            return None
        return parts[0], parts[1], parts[2]
    except Exception:
        return None


def _parse_host_header(headers: bytes) -> Optional[str]:
    # Very simple Host header extraction
    m = re.search(br"(?im)^host:\s*([^\r\n]+)\r?$", headers)
    if not m:
        return None
    try:
        return m.group(1).decode("utf-8", errors="ignore").strip()
    except Exception:
        return None


def _split_host_port(host_value: str, default_port: int) -> Tuple[str, int]:
    hv = host_value.strip()
    if hv.startswith("["):
        end = hv.find("]")
        if end != -1 and end + 1 < len(hv) and hv[end + 1] == ":":
            try:
                return hv[1:end], int(hv[end + 2 :])
            except ValueError:
                return hv[1:end], default_port
        return hv.strip("[]"), default_port

    if ":" in hv:
        h, p = hv.rsplit(":", 1)
        try:
            return h, int(p)
        except ValueError:
            return h, default_port

    return hv, default_port


async def handle_connect(
    local_reader: asyncio.StreamReader,
    local_writer: asyncio.StreamWriter,
    cfg: Config,
    logger: logging.Logger,
    metrics: Metrics,
    host: str,
    port: int,
) -> None:
    metrics.connect_tunnels += 1

    try:
        if cfg.upstream.enabled:
            if not cfg.upstream.host or not cfg.upstream.port:
                raise RuntimeError("upstream.enabled=true but upstream.host/port is not set")
            logger.info(
                "dial upstream %s:%d for %s:%d (prefer_ipv4=%s timeout=%.1fs)",
                cfg.upstream.host,
                cfg.upstream.port,
                host,
                port,
                cfg.prefer_ipv4,
                cfg.dial_timeout_s,
            )
            remote_reader, remote_writer = await dial_direct(cfg, cfg.upstream.host, cfg.upstream.port)
            await upstream_http_connect(remote_reader, remote_writer, host, port, timeout_s=cfg.dial_timeout_s)
        else:
            logger.info("dial %s:%d (prefer_ipv4=%s timeout=%.1fs)", host, port, cfg.prefer_ipv4, cfg.dial_timeout_s)
            remote_reader, remote_writer = await dial_direct(cfg, host, port)
    except Exception as e:
        logger.info("dial failed %s:%d: %r", host, port, e)
        local_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await local_writer.drain()
        return

    local_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    await local_writer.drain()

    try:
        if port == 443:
            # Read the first TLS record from client (likely ClientHello).
            # Some Chrome background connections may CONNECT and then immediately close without TLS.
            try:
                head = await asyncio.wait_for(local_reader.readexactly(5), timeout=2.0)
            except asyncio.TimeoutError:
                logger.info("TLS first record not received yet (tunnel passthrough) host=%s", host)
                head = None
            except asyncio.IncompleteReadError:
                logger.info("client closed before TLS (tunnel abort) host=%s", host)
                return

            if head is None:
                # Just tunnel without any TLS inspection.
                t1 = asyncio.create_task(pipe(local_reader, remote_writer))
                t2 = asyncio.create_task(pipe(remote_reader, local_writer))
                done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
                for t in pending:
                    t.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                return

            rec_type = head[0:1]
            ver = head[1:3]
            length = int.from_bytes(head[3:5], "big")
            try:
                payload = await asyncio.wait_for(local_reader.readexactly(length), timeout=2.0)
            except asyncio.TimeoutError:
                logger.info("TLS payload timeout (abort) host=%s len=%d", host, length)
                return
            except asyncio.IncompleteReadError:
                logger.info("TLS payload incomplete (abort) host=%s len=%d", host, length)
                return

            metrics.tls_clienthello_seen += 1

            # Only parse SNI if we actually have rules.
            sni = None
            action = "pass"
            rule = None
            sni_range: Optional[Tuple[int, int]] = None
            if cfg.rules:
                # TLS handshake record type is 0x16
                if head[0] == 0x16:
                    sni_info = parse_tls_sni_range_from_client_hello_record(payload)
                    if sni_info:
                        sni, s_start, s_end = sni_info
                        sni_range = (s_start, s_end)
                    else:
                        sni = parse_tls_sni_from_client_hello_record(payload)
                action = match_action(sni or host, cfg.rules, cfg.domain_matching)
                rule = match_rule(sni or host, cfg.rules, cfg.domain_matching)

            frag = _effective_fragment_config(cfg.fragment, rule)

            do_fragment = frag.enabled and action == "fragment" and length <= frag.max_payload

            if do_fragment:
                metrics.tls_fragmented += 1

                slices = _build_fragment_slices(payload, frag, sni_range)
                logger.info(
                    "TLS fragment=yes host=%s sni=%s strat=%s parts=%d jitter=%d..%dms",
                    host,
                    sni,
                    frag.strategy,
                    len(slices),
                    frag.jitter_ms_min,
                    frag.jitter_ms_max,
                )

                for i, part in enumerate(slices):
                    remote_writer.write(rec_type + ver + int(len(part)).to_bytes(2, "big") + part)
                    await remote_writer.drain()

                    if i + 1 < len(slices) and frag.jitter_ms_max > 0:
                        mn = max(0, int(frag.jitter_ms_min or 0))
                        mx = max(mn, int(frag.jitter_ms_max or mn))
                        await asyncio.sleep(random.uniform(mn, mx) / 1000.0)
            else:
                logger.info("TLS fragment=no host=%s sni=%s action=%s", host, sni, action)
                remote_writer.write(head + payload)
                await remote_writer.drain()

        t1 = asyncio.create_task(pipe(local_reader, remote_writer))
        t2 = asyncio.create_task(pipe(remote_reader, local_writer))
        done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    finally:
        try:
            remote_writer.close()
        except Exception:
            pass


async def handle_http(
    local_reader: asyncio.StreamReader,
    local_writer: asyncio.StreamWriter,
    cfg: Config,
    logger: logging.Logger,
    metrics: Metrics,
    headers: bytes,
    method: str,
    target: str,
    version: str,
) -> None:
    metrics.http_requests += 1

    # Proxy absolute-form: GET http://host/path HTTP/1.1
    # We'll parse Host from header first; if missing, try from URL.
    host_hdr = _parse_host_header(headers)

    # Basic url parse (no urllib to keep it tiny & predictable)
    url = target
    host_from_url = None
    path_from_url = None
    if url.startswith("http://"):
        rest = url[len("http://") :]
        if "/" in rest:
            host_from_url, path_from_url = rest.split("/", 1)
            path_from_url = "/" + path_from_url
        else:
            host_from_url, path_from_url = rest, "/"

    host_val = host_hdr or host_from_url
    if not host_val:
        local_writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
        await local_writer.drain()
        return

    host, port = _split_host_port(host_val, default_port=80)
    path = path_from_url or target
    if not path.startswith("/"):
        path = "/" + path

    try:
        logger.info("dial http %s:%d (prefer_ipv4=%s timeout=%.1fs)", host, port, cfg.prefer_ipv4, cfg.dial_timeout_s)
        remote_reader, remote_writer = await dial(cfg, host, port)
    except Exception as e:
        logger.info("HTTP dial failed %s:%d: %r", host, port, e)
        local_writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        await local_writer.drain()
        return

    try:
        # Rebuild request line to origin-form
        req_line = f"{method} {path} {version}\r\n".encode("iso-8859-1")

        # Remove Proxy-Connection header (common but non-standard)
        sanitized = re.sub(br"(?im)^proxy-connection:\s*.*\r?\n", b"", headers)

        # Replace first line with origin-form line
        split = sanitized.split(b"\r\n", 1)
        if len(split) == 2:
            rest_headers = split[1]
        else:
            rest_headers = b"\r\n\r\n"

        remote_writer.write(req_line + rest_headers)
        await remote_writer.drain()

        # Pipe the rest both ways
        t1 = asyncio.create_task(pipe(local_reader, remote_writer))
        t2 = asyncio.create_task(pipe(remote_reader, local_writer))
        done, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await asyncio.gather(*pending, return_exceptions=True)

    finally:
        try:
            remote_writer.close()
        except Exception:
            pass


async def handle_client(
    local_reader: asyncio.StreamReader,
    local_writer: asyncio.StreamWriter,
    cfg: Config,
    logger: logging.Logger,
    metrics: Metrics,
) -> None:
    metrics.connections_total += 1
    metrics.connections_active += 1

    try:
        headers = await read_http_headers(local_reader, timeout_s=5.0)
        first = headers.split(b"\r\n", 1)[0] if headers else b""
        parsed = _parse_http_request_line(first)
        if not parsed:
            return

        method, target, version = parsed

        if method.upper() == "CONNECT":
            t = parse_connect_target(target)
            if not t:
                return
            host, port = t
            logger.info("CONNECT %s:%d", host, port)
            await handle_connect(local_reader, local_writer, cfg, logger, metrics, host, port)
            return

        # Plain HTTP proxy mode
        logger.info("HTTP %s %s", method, target)
        await handle_http(local_reader, local_writer, cfg, logger, metrics, headers, method, target, version)

    except Exception as e:
        if cfg.verbose:
            logger.exception("client handler error")
        else:
            # Keep the log clean: some clients close early, which is expected.
            if isinstance(e, asyncio.IncompleteReadError):
                logger.info("client closed early")
            else:
                logger.info("client handler error: %r", e)
    finally:
        metrics.connections_active -= 1
        try:
            local_writer.close()
        except Exception:
            pass


def pac_js(host: str, port: int) -> str:
    # Minimal PAC: route everything through our proxy.
    return (
        "function FindProxyForURL(url, host) {\n"
        f"  return 'PROXY {host}:{port}; DIRECT';\n"
        "}\n"
    )


async def pac_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, cfg: Config) -> None:
    try:
        data = await reader.read(4096)
        if b"GET" not in data:
            return
        body = pac_js(cfg.proxy_host, cfg.proxy_port).encode("utf-8")
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/x-ns-proxy-autoconfig\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )
        writer.write(resp)
        await writer.drain()
    finally:
        try:
            writer.close()
        except Exception:
            pass


def doctor(cfg: Config) -> int:
    print(banner())
    print("\nSelf-test (doctor)\n")

    py_ok = sys.version_info >= (3, 8)
    print(f"[{'OK' if py_ok else 'FAIL'}] Python: {sys.version.split()[0]} (need >= 3.8)")

    ok1, msg1 = check_port_available(cfg.proxy_host, cfg.proxy_port)
    print(f"[{'OK' if ok1 else 'FAIL'}] Bind proxy {cfg.proxy_host}:{cfg.proxy_port}: {msg1}")

    ok2, msg2 = check_port_available(cfg.proxy_host, cfg.pac_port)
    print(f"[{'OK' if ok2 else 'FAIL'}] Bind PAC  {cfg.proxy_host}:{cfg.pac_port}: {msg2}")

    print("\nNext steps:")
    pycmd = "py" if os.name == "nt" else "python3"
    print(f"- Start: {pycmd} dgen_nodpi.py run")
    print(f"- PAC :  http://{cfg.proxy_host}:{cfg.pac_port}/proxy.pac")
    print(f"- Proxy: {cfg.proxy_host}:{cfg.proxy_port}")
    if os.name == "nt":
        print(f"- Autostart (optional): {pycmd} dgen_nodpi.py install | status | uninstall")

    all_ok = py_ok and ok1 and ok2
    return 0 if all_ok else 2


async def run_async(cfg: Config, logger: logging.Logger, show_banner: bool = True) -> None:
    # Reduce noisy Windows asyncio callback tracebacks (e.g. WinError 10054).
    try:
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(_asyncio_exception_handler)
    except Exception:
        pass

    metrics = Metrics()

    proxy = await asyncio.start_server(
        lambda r, w: handle_client(r, w, cfg, logger, metrics),
        cfg.proxy_host,
        cfg.proxy_port,
    )

    pac = await asyncio.start_server(
        lambda r, w: pac_handler(r, w, cfg),
        cfg.proxy_host,
        cfg.pac_port,
    )

    logger.info("PAC server: http://%s:%d/proxy.pac", cfg.proxy_host, cfg.pac_port)

    if show_banner:
        print(banner())
        print()
    print(f"Proxy: {cfg.proxy_host}:{cfg.proxy_port}")
    print(f"PAC  : http://{cfg.proxy_host}:{cfg.pac_port}/proxy.pac")
    print("Stop : Ctrl+C")

    # Start live stats only after we printed the header, so it never appears above the banner.
    stats_task: Optional[asyncio.Task] = None
    if not cfg.verbose and (cfg.console.mode == "stats"):
        print()  # reserve a line for stats
        stats_task = asyncio.create_task(_stats_loop(metrics))

    try:
        # Run both servers until cancelled (Ctrl+C in asyncio.run).
        await asyncio.gather(proxy.serve_forever(), pac.serve_forever())
    except asyncio.CancelledError:
        # Expected on shutdown.
        pass
    finally:
        if stats_task:
            stats_task.cancel()
            await asyncio.gather(stats_task, return_exceptions=True)
        proxy.close()
        pac.close()
        await proxy.wait_closed()
        await pac.wait_closed()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dgen_nodpi.py")
    p.add_argument("--config", default=DEFAULT_CONFIG_PATH, help="Path to config JSON")

    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("run", help="Run proxy + PAC server")
    sub.add_parser("doctor", help="Self-test")
    sub.add_parser("pac", help="Print PAC URL and contents")
    sub.add_parser("version", help="Print version")
    sub.add_parser("enable-youtube", help="Enable recommended YouTube fragmentation rules in config")
    sub.add_parser("install", help="Install autostart (Windows) to run proxy on login")
    sub.add_parser("uninstall", help="Remove autostart (Windows)")
    sub.add_parser("status", help="Show autostart status (Windows)")
    return p


def _prompt_choice(title: str, choices: List[Tuple[str, str]]) -> str:
    """Small helper for interactive menus.

    choices: list of (key, label)
    returns chosen key (string)
    """
    print(title)
    for k, label in choices:
        print(f"{k}) {label}")
    return input("> ").strip()


def _clear_screen() -> None:
    try:
        os.system("cls" if os.name == "nt" else "clear")
    except Exception:
        pass


def _pause(msg: str = "\nНажмите Enter, чтобы продолжить...") -> None:
    try:
        input(msg)
    except Exception:
        pass


def _cmd_enable_youtube(cfg_path: str) -> int:
    # Reload raw (don't rely on parsed cfg), update and save.
    raw = load_config(cfg_path)
    frag = raw.get("fragment")
    if not isinstance(frag, dict):
        frag = {}
        raw["fragment"] = frag
    frag["enabled"] = True

    raw["rules"] = YOUTUBE_RULES
    save_raw_config(cfg_path, raw)

    print("Enabled YouTube rules in config:")
    for r in YOUTUBE_RULES:
        print(f"- {r['suffix']}: {r['action']}")
    print(f"\nSaved: {cfg_path}")
    return 0


def interactive_menu(cfg_path: str, cfg: Config, logger: logging.Logger) -> int:
    """Interactive menu for users who don't want to type commands."""
    while True:
        _clear_screen()
        print(banner())
        print()
        choice = _prompt_choice(
            "Меню:",
            [
                ("1", "Start proxy + PAC (run)"),
                ("2", "Doctor (self-test)"),
                ("3", "Show PAC URL and contents (pac)"),
                ("4", "Enable YouTube preset (enable-youtube)"),
                ("5", "Autostart status (Windows)"),
                ("6", "Autostart install (Windows)"),
                ("7", "Autostart uninstall (Windows)"),
                ("0", "Exit"),
            ],
        )

        if choice == "0":
            return 0
        if choice == "1":
            try:
                _clear_screen()
                asyncio.run(run_async(cfg, logger, show_banner=True))
            except KeyboardInterrupt:
                print("\nStopped.")
            continue
        if choice == "2":
            _clear_screen()
            doctor(cfg)
            _pause()
            continue
        if choice == "3":
            _clear_screen()
            print(f"PAC URL: http://{cfg.proxy_host}:{cfg.pac_port}/proxy.pac")
            print("\n--- proxy.pac ---\n")
            print(pac_js(cfg.proxy_host, cfg.proxy_port))
            _pause()
            continue
        if choice == "4":
            _clear_screen()
            _cmd_enable_youtube(cfg_path)
            # reload config in case user starts run afterwards
            cfg = parse_config(load_config(cfg_path))
            logger = setup_logging(cfg.log_path, cfg.verbose)
            _pause()
            continue

        if choice == "5":
            _clear_screen()
            try:
                cur = autostart_status()
                if cur:
                    print("Autostart: installed")
                    print(f"Name    : {AUTOSTART_REG_NAME}")
                    print(f"Command : {cur}")
                else:
                    print("Autostart: not installed")
            except Exception as e:
                _eprint(f"status failed: {e!r}")
            _pause()
            continue

        if choice == "6":
            _clear_screen()
            try:
                cmd = _build_autostart_command(cfg_path)
                autostart_install(cmd)
                print("Installed autostart.")
                print(f"Name   : {AUTOSTART_REG_NAME}")
                print(f"Command: {cmd}")
            except Exception as e:
                _eprint(f"install failed: {e!r}")
            _pause()
            continue

        if choice == "7":
            _clear_screen()
            try:
                autostart_uninstall()
                print("Removed autostart.")
            except Exception as e:
                _eprint(f"uninstall failed: {e!r}")
            _pause()
            continue
        print("Unknown option.")


def _require_windows_autostart() -> None:
    if os.name != "nt" or winreg is None:
        raise RuntimeError("autostart is only supported on Windows")


def _build_autostart_command(cfg_path: str) -> str:
    # Use the same Python interpreter that runs this command.
    # This makes autostart work even when 'py' is not on PATH.
    exe = sys.executable
    script = os.path.abspath(__file__)
    # Start only proxy+PAC (do NOT launch a browser).
    return f'"{exe}" "{script}" run --config "{cfg_path}"'


def autostart_status() -> Optional[str]:
    _require_windows_autostart()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_RUN_KEY, 0, winreg.KEY_READ) as k:
            val, _typ = winreg.QueryValueEx(k, AUTOSTART_REG_NAME)
            if isinstance(val, str) and val.strip():
                return val
            return None
    except FileNotFoundError:
        return None
    except OSError:
        return None


def autostart_install(command: str) -> None:
    _require_windows_autostart()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, AUTOSTART_REG_NAME, 0, winreg.REG_SZ, command)


def autostart_uninstall() -> None:
    _require_windows_autostart()
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTOSTART_RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        try:
            winreg.DeleteValue(k, AUTOSTART_REG_NAME)
        except FileNotFoundError:
            pass


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    cfg_path = args.config
    if cfg_path and not os.path.isabs(cfg_path):
        cfg_path = os.path.join(SCRIPT_DIR, cfg_path)

    raw = load_config(cfg_path)
    cfg = parse_config(raw)

    logger = setup_logging(cfg.log_path, cfg.verbose)

    banner_printed = False
    # If user runs without a subcommand, show a small prompt:
    # 1) start immediately
    # 2) open menu
    if not args.cmd:
        _clear_screen()
        print(banner())
        print()
        first = _prompt_choice(
            "Выберите режим:",
            [
                ("1", "Старт (запуск proxy + PAC)"),
                ("2", "Меню"),
                ("0", "Выход"),
            ],
        )
        if first == "0":
            return 0
        if first == "1":
            _clear_screen()
            args.cmd = "run"
        else:
            args.cmd = "menu"

    if args.cmd == "version":
        print(VERSION)
        return 0

    if args.cmd == "status":
        try:
            cur = autostart_status()
            if cur:
                print("Autostart: installed")
                print(f"Name    : {AUTOSTART_REG_NAME}")
                print(f"Command : {cur}")
            else:
                print("Autostart: not installed")
            return 0
        except Exception as e:
            _eprint(f"status failed: {e!r}")
            return 2

    if args.cmd == "install":
        try:
            cmd = _build_autostart_command(cfg_path)
            autostart_install(cmd)
            print("Installed autostart.")
            print(f"Name   : {AUTOSTART_REG_NAME}")
            print(f"Command: {cmd}")
            return 0
        except Exception as e:
            _eprint(f"install failed: {e!r}")
            return 2

    if args.cmd == "uninstall":
        try:
            autostart_uninstall()
            print("Removed autostart.")
            return 0
        except Exception as e:
            _eprint(f"uninstall failed: {e!r}")
            return 2

    if args.cmd == "doctor":
        return doctor(cfg)

    if args.cmd == "pac":
        print(f"PAC URL: http://{cfg.proxy_host}:{cfg.pac_port}/proxy.pac")
        print("\n--- proxy.pac ---\n")
        print(pac_js(cfg.proxy_host, cfg.proxy_port))
        return 0

    if args.cmd == "enable-youtube":
        return _cmd_enable_youtube(cfg_path)

    if args.cmd == "menu":
        if not banner_printed:
            print(banner())
        return interactive_menu(cfg_path, cfg, logger)

    # default: run
    try:
        asyncio.run(run_async(cfg, logger, show_banner=True))
    except KeyboardInterrupt:
        print("\nStopped.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
