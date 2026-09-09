## What this is
A small collection of standalone Python security utilities: a file-integrity monitor (FIM), a web-security header checker, a suspicious-login activity detector (SLAD), and a DNS-based Wi‑Fi activity logger. Each is a single-script tool you run from the command line to analyze files, HTTP headers, login logs, or live DNS traffic.

### Stack
- **Language(s):** Python (100%)
- **Framework / runtime:** CPython 3.x (scripts are plain Python)
- **Notable libraries:** requests (web security checker), scapy (wifi DNS monitor). Standard library used for the other scripts (hashlib, json, csv, datetime, os, threading).

## How it's organized
Top-level files (annotated):
```text
README.md                 repo description + short usage notes
FIM2.PY                   File Integrity Monitor — hashes files under a folder, creates/updates baseline.json
web security checker      Web security header checker (script that issues an HTTP GET and inspects headers)
SLAD.py                   Suspicious Login Activity Detector — parses login event logs and reports suspicious patterns
wifi log monitor.py       DNS-based Wi‑Fi DNS-query logger; captures DNS packets and appends to CSV
```

How it fits together:
- These are separate CLI scripts (no shared library). Each script is an independent tool you run when you need that check. There is no central runner; they operate on file input (FIM, SLAD), user-entered URL (web checker), or live packet capture (wifi monitor).

## Per-program explanation, uses, and required input

1) FIM2.PY — File Integrity Monitor
- Purpose / use: Walks a directory tree, computes SHA‑256 hashes of each file, and compares them to a baseline stored in baseline.json. It reports new, modified, or deleted files and can update the baseline.
- Required input: When started it prompts:
  - Enter folder name or path: supply an absolute or relative directory path to monitor (e.g., /home/user/documents or ./myproject).
- Behavior notes:
  - If baseline.json does not exist it creates it from the current directory state and instructs you to run again to check for changes.
  - On subsequent runs it compares current hashes to baseline.json and reports [NEW FILE], [MODIFIED], or [DELETED].
  - After reporting it asks: Update baseline with current state? (y/n).
- Dependencies: Python standard library only.
- Command example:
  - python3 FIM2.PY

2) web security checker — Web Security Header Checker
- Purpose / use: Makes an HTTP(S) request to a URL and inspects key security-related response headers (Strict-Transport-Security, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options). It computes a simple score (0–100 scale pieces added) and prints whether the site redirects.
- Required input: When started it prompts:
  - Enter URL: provide the site URL. The script will prepend https:// if no scheme is present (so both "example.com" and "https://example.com" work). README suggests starting with https:// but script handles missing scheme.
- Behavior notes:
  - Prints final URL (after redirects), HTTP status, headers found (or "Header not found") and a numeric score based on scheme, redirect, and presence of headers.
  - If the site returns an HTTP error (>=400) the headers are still inspected but a warning is printed.
- Dependencies: requests library
- Command example:
  - pip install requests
  - python3 "web security checker"

3) SLAD.py — Suspicious Login Activity Detector
- Purpose / use: Reads a plaintext log file of login events, counts successful/failed logins, tallies failed attempts by IP and user, flags IPs with many failures (brute-force candidates) and detects successful logins that followed multiple recent failed attempts (possible compromise).
- Required input: When started it prompts:
  - Enter log file name: a file path or filename. The script searches the current working directory and the script directory if the provided name is relative.
- Expected log file format (important): the script expects each log line to have at least 5 whitespace-separated parts where:
  - parts[0] = date in YYYY‑MM‑DD,
  - parts[1] = time in HH:MM:SS,
  - parts[2] = event token, expected values: LOGIN_SUCCESS or LOGIN_FAILED,
  - parts[3] contains user info in the form user=<username>,
  - parts[4] contains ip info in the form ip=<ip-address>.
  Example line the parser accepts:
    2026-09-09 12:34:56 LOGIN_FAILED user=alice ip=192.0.2.1
- Behavior notes:
  - FAIL_LIMIT is set to 5 (IPs with ≥5 failed logins are reported as potential brute force).
  - TIME_LIMIT is 2 minutes: if a LOGIN_SUCCESS happens after ≥3 LOGIN_FAILED for the same user+IP within 2 minutes, the script lists it as potential compromise.
- Dependencies: Python standard library only.
- Command example:
  - python3 SLAD.py
  - then supply the path to your formatted log file

4) wifi log monitor.py — Wi‑Fi DNS Log Monitor
- Purpose / use: Live-captures DNS query packets on the host network interface, logs timestamp, source IP and queried domain to a CSV file (default activity_log.csv). Useful for auditing DNS lookups on a Wi‑Fi network or device.
- Required input / environment:
  - No interactive prompt. It uses an output log path from the environment variable WIFI_LOG_FILE (optional) or defaults to activity_log.csv in the script directory.
  - Must be run with packet-capture privileges (root/Administrator or appropriate capabilities).
- Behavior notes:
  - Uses scapy to sniff UDP/TCP port 53, filters for DNS queries only, extracts qname, and appends rows to CSV with header ["Timestamp","Source_IP","Domain"].
  - Implements safe CSV escaping for potential injection, log rotation when file exceeds 5 MB (keeps up to 3 backups).
  - Prints each captured query to stdout.
- Dependencies:
  - scapy (and system libpcap or Npcap installed); on Windows requires Npcap and admin rights.
- Important: packet capture usually requires root/admin privileges and libpcap/Npcap. Running without privileges will raise a capture error.
- Command example:
  - pip install scapy
  - sudo python3 "wifi log monitor.py"
  - (or run as Administrator on Windows and ensure Npcap is installed)

## How to run it
Shortest path from a fresh clone:
1. Ensure Python 3.x is installed.
2. (Optional) create a venv:
   - python3 -m venv venv && source venv/bin/activate
3. Install dependencies needed:
   - pip install requests scapy
4. Run the script you want:
   - python3 FIM2.PY                # follow prompt for folder path
   - python3 "web security checker" # enter URL when prompted
   - python3 SLAD.py                # enter path to login log file
   - sudo python3 "wifi log monitor.py"  # requires elevated privileges

Notes:
- wifi log monitor requires libpcap/Npcap and capture privileges.
- SLAD requires logs in the expected format (see examples above).
- FIM2 will create baseline.json in the working directory.

