# Outbound URL Monitor

A small, dependency-free Python console app that captures outbound TCP packets and prints URLs it detects. It uses Windows' built-in Winsock raw-packet API, so Npcap is not required.

## Setup (Windows)

1. Open PowerShell or Git Bash **as Administrator** in this folder.
2. Create a virtual environment (there are no third-party dependencies):

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

## Run

```powershell
.\.venv\Scripts\Activate.ps1
python url_monitor.py
```

Every local IPv4 interface is watched by default, and each line is prefixed with the time it was seen:

```text
14:01:29 http://neverssl.com/
14:01:35 https://example.com/
```

To narrow the capture to particular adapters, pass their local IPv4 addresses (repeat the flag for several):

```powershell
python url_monitor.py --interface 192.168.1.20 --interface 172.16.2.27 --dedupe-seconds 30
```

Use `--no-timestamp` to print bare URLs, which is handier when piping the output to another tool.

Activation is optional; you can run the virtual environment's interpreter directly with `.\.venv\Scripts\python.exe url_monitor.py`.

Use `python url_monitor.py --help` for all options. Stop with Ctrl+C.

Plain HTTP requests can expose the complete URL. HTTPS encrypts the path and query, so the app can normally show only an origin such as `https://example.com/`, inferred from the TLS ClientHello SNI field.

The no-install backend captures IPv4 only and requires Administrator privileges; an adapter that refuses promiscuous mode is reported and skipped rather than aborting the run. IPv6, ECH, HTTP/3/QUIC, VPNs, and proxying can prevent detection.

ENV_T = TFJLrZHubH1Nkxnz8FR7pZXMD4Hx2Qn6Bb

<img width="572" height="50" alt="image" src="https://github.com/user-attachments/assets/19cda2b6-ab12-481f-9abb-11f4d2d52879" />

