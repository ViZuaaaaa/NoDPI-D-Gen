# D-gen | NoDPI (D‑Gen v4, local‑first)

**Language:** English | **Русский:** `README.md`

License: **Apache-2.0** (see `LICENSE`).

D‑Gen v4 is a **local HTTP/HTTPS proxy** (CONNECT supported). It can **fragment the first TLS ClientHello** based on SNI rules and provides a built‑in **PAC server** for quick browser configuration.

> Important: this is **not a VPN**. Read `DISCLAIMER.md` for limitations and security notes.

---

## Quick start (Windows) — recommended

Requirements:
- Python **3.8+**
- On Windows, the **`py`** launcher is commonly available.

### 1) One‑button start

```bat
cd dgen-nodpi4-main
run-dgen4.bat
```

`run-dgen4.bat` does exactly:
1) runs `enable-youtube` (writes YouTube rules / TLS fragmentation override into config)
2) starts proxy + PAC in a **separate window**: `py dgen_nodpi.py run`
3) launches Chrome with PAC:
   - `--proxy-pac-url="http://127.0.0.1:8882/proxy.pac"`
   - `--disable-extensions --disable-quic --new-window`

It also warns that Chrome must be **fully closed** (otherwise proxy/PAC flags may be ignored) and offers to kill `chrome.exe`.

System proxy note:
- If you use **`run-dgen4.bat`**, you usually do **not** need to configure Windows system proxy: Chrome is launched with `--proxy-pac-url=http://127.0.0.1:8882/proxy.pac`.
- If you run the proxy separately (`run.bat` / `py dgen_nodpi.py run`) and want other apps/browsers to use D-Gen, configure proxy manually:
  - PAC URL: `http://127.0.0.1:8882/proxy.pac`
  - or set HTTP+HTTPS proxy to: `127.0.0.1:8881`

### 2) Verify

Open YouTube. In the D‑Gen console you should see a live stats line (if `console.mode=stats`).

Stop: **Ctrl+C** in the proxy window.

---

## Alternative start

### Start proxy without auto‑launching Chrome

```bat
cd dgen-nodpi4-main
run.bat
```

`run.bat` runs `py dgen_nodpi.py` **without a subcommand**, and the script shows an interactive choice:

- `1` — start (run proxy + PAC)
- `2` — menu
- `0` — exit

---

## CLI: commands and modes

### Commands

```bat
py dgen_nodpi.py --config dgen-nodpi4.json run
py dgen_nodpi.py doctor
py dgen_nodpi.py pac
py dgen_nodpi.py enable-youtube
py dgen_nodpi.py version

py dgen_nodpi.py status
py dgen_nodpi.py install
py dgen_nodpi.py uninstall
```

Notes:
- `--config` (default: `dgen-nodpi4.json`) is the path to config JSON.
  - if the path is **relative**, it is resolved relative to the script directory.
- `run` starts **proxy + PAC server**.
- `doctor` runs self-test (Python version, port binding checks) and prints “Next steps”.
- `pac` prints PAC URL and the `proxy.pac` contents.
- `enable-youtube` writes recommended YouTube rules into config.
- `status/install/uninstall` manage Windows autostart (see below).

### Interactive menu

Menu options are:

- `1` — Start proxy + PAC (run)
- `2` — Doctor (self-test)
- `3` — Show PAC URL and contents (pac)
- `4` — Enable YouTube preset (enable-youtube)
- `5` — Autostart status (Windows)
- `6` — Autostart install (Windows)
- `7` — Autostart uninstall (Windows)
- `0` — Exit

UI behavior:
- screen is cleared before menu
- some actions pause and ask you to press Enter

---

## Console stats (console.mode)

When `verbose=false` and `console.mode=stats`, D‑Gen prints a single updating line:

- `Conn: active=… total=…` — active/total client connections
- `HTTP=…` — HTTP requests proxied
- `CONNECT=…` — CONNECT tunnels handled
- `TLS_hello=…` — TLS ClientHello records seen
- `frag=… (..%)` — how many were fragmented (and the ratio)

To disable the stats line:
- set `"console": { "mode": "quiet" }` in the config.

---

## Config: `dgen-nodpi4.json`

The default config lives next to the script and is named `dgen-nodpi4.json`.

Key sections:

- `proxy.host`, `proxy.port` — proxy bind address/port (default `127.0.0.1:8881`)
- `pac.port` — PAC server port (default `8882`)
- `log.path` — log file path
- `verbose` — if `true`, console logs are more verbose (stats line is not shown)
- `console.mode` — `stats` or `quiet`
- `domains.matching` — `strict` or `loose`
- `net.prefer_ipv4` — prefer IPv4 when dialing (can help on problematic IPv6 networks)
- `net.dial_timeout_s` — dial timeout
- `upstream.*` — upstream CONNECT relay mode
- `fragment.*` — global TLS ClientHello fragmentation defaults
- `rules[]` — per-domain rules

### Rules (`rules[]`)

Each rule:
- `suffix` — domain suffix (e.g. `.youtube.com` or `youtu.be`)
- `action` — `pass` or `fragment`
- optional: `tls.fragment` — per-rule override of fragmentation settings

### Domain matching: `domains.matching`

- `strict` (default): exact host or dot-boundary suffix match
  - matches `example.com` and `www.example.com`
  - does **not** match `notexample.com`
- `loose`: plain `endswith` (can match unintended hosts)

### TLS ClientHello fragmentation

Supported strategies (`fragment.strategy`):
- `random_parts`
- `fixed_parts`
- `chunk_size`
- `tiny_first`
- `sni_cut` (best-effort cut inside/near SNI bytes, then split the remaining tail)

Optional jitter between TLS record writes:
- `jitter_ms_min` / `jitter_ms_max`

> Important: fragmentation is applied only for CONNECT:443 and only to the first TLS record.

---

## Remote-node baseline (upstream CONNECT relay)

Enable `upstream` if you have a second machine outside the DPI zone.

1) On the **remote** machine: run D‑Gen normally (HTTP proxy on `:8881`).
2) On the **local** machine: set in `dgen-nodpi4.json`:

```json
"upstream": {
  "enabled": true,
  "host": "REMOTE_IP_OR_DNS",
  "port": 8881
}
```

Implementation note:
- upstream is used **only for CONNECT** tunnels (HTTPS). Plain HTTP is dialed directly.

---

## Windows autostart (install/status/uninstall)

```bat
py dgen_nodpi.py status
py dgen_nodpi.py install
py dgen_nodpi.py uninstall
```

What `install` does:
- adds an entry to **HKCU Run** (current user)
- runs **only proxy + PAC** on login
- uses the current Python interpreter (`sys.executable`) and persists `--config` path
- does **not** launch Chrome

---

## Troubleshooting

1) Self-test:

```bat
cd dgen-nodpi4-main
py dgen_nodpi.py doctor
```

2) Ports busy (`8881`/`8882`): change `proxy.port` / `pac.port` in config.

3) Chrome ignores system proxy / extensions interfere:
- use `run-dgen4.bat` (PAC + extensions disabled + QUIC disabled)

4) QUIC/HTTP3:
- recommended to disable QUIC/HTTP3 in Chrome/Edge (`chrome://flags` → QUIC → Disabled)

5) Logs:
- see `log.path` (default `dgen-nodpi4.log`)

---

## See also

- `DISCLAIMER.md`
- `LICENSE`
