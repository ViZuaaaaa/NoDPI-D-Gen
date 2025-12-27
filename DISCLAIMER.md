# Disclaimer / limitations

- This project is provided **as-is** with no warranties.
- It is a **local HTTP/HTTPS proxy**. It is **not a VPN** and it does **not** provide end-to-end encryption.
- Success is **not guaranteed** and depends on your network conditions.
- This tool does not solve **IP-based blocking**.

## Legal

You are responsible for complying with local laws and network policies.

## Security

- Default bind address is `127.0.0.1` (loopback). **Do not expose** the proxy to the public Internet.
- There is **no authentication**. If you bind to `0.0.0.0`, anyone on your LAN may be able to use it.
- If you use upstream (remote-node) mode, secure the transport (firewall/VPN/TLS) and do not treat it as a safe public relay.
