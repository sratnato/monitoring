#!/usr/bin/env python3
"""
Watch DNS A/AAAA answers for one or more hostnames and log when they change.

Usage examples:
  python3 ip_watch.py directions-proxy.onrender.com
  python3 ip_watch.py https://directions-proxy.onrender.com
  python3 ip_watch.py host1.onrender.com host2.example.com \
    --state-dir state --log-file ip_changes.log --retries 2

Exit codes:
  0 = ok (no lookup errors)
  2 = at least one hostname failed to resolve
"""

import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlparse


# ---------- helpers ----------

def iso_now() -> str:
    """Return an ISO8601 UTC timestamp (e.g., 2025-11-10T09:22:00+00:00)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_host(s: str) -> str:
    """
    Accept a hostname or URL and return the bare hostname (no scheme/path/port).
    Examples:
      'https://foo.onrender.com/' -> 'foo.onrender.com'
      'foo.onrender.com:443' -> 'foo.onrender.com'
    """
    s = s.strip()
    if "://" in s:
        parsed = urlparse(s)
        host = parsed.netloc or parsed.path
    else:
        host = s.split("/")[0]
    return host.split(":")[0]


def resolve_all(host: str, retries: int):
    """
    Return a sorted list of unique IPv4/IPv6 addresses for host.
    Uses system resolver via socket.getaddrinfo (no external deps).
    """
    host = normalize_host(host)
    ips = set()
    last_err = None
    for _ in range(retries + 1):
        try:
            # type=STREAM to avoid duplicates; port 0 is fine for DNS lookup
            infos = socket.getaddrinfo(host, 0, type=socket.SOCK_STREAM)
            for _family, _socktype, _proto, _canonname, sockaddr in infos:
                ips.add(sockaddr[0])  # IPv4 or IPv6 literal
            return sorted(ips)
        except Exception as e:
            last_err = e
            time.sleep(0.3)
    raise last_err


def load_state(path: str):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # corrupted or unreadable -> start fresh (don't crash the job)
        return {}


def save_state(path: str, data: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def append_log(line: dict, log_file: str):
    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(line) + "\n")


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="Log when DNS answers change.")
    ap.add_argument("hostnames", nargs="+", help="Hostnames or URLs to watch")
    ap.add_argument("--state-dir", default=".state", help="Directory for state file")
    ap.add_argument("--log-file", default="ip_changes.log", help="Path to log file")
    ap.add_argument("--retries", type=int, default=2, help="DNS retry attempts")
    args = ap.parse_args()

    state_path = os.path.join(args.state_dir, "last_ips.json")
    state = load_state(state_path)
    changed_any = False
    exit_code = 0

    for host_input in args.hostnames:
        host = normalize_host(host_input)
        try:
            current_ips = resolve_all(host, args.retries)
        except Exception as e:
            append_log({
                "ts": iso_now(),
                "level": "error",
                "event": "dns_lookup_failed",
                "host": host,
                "error": str(e),
            }, args.log_file)
            exit_code = 2
            continue

        prev_ips = state.get(host, [])
        if sorted(prev_ips) != current_ips:
            changed_any = True
            append_log({
                "ts": iso_now(),
                "level": "info",
                "event": "ip_changed",
                "host": host,
                "before": prev_ips,
                "after": current_ips,
            }, args.log_file)
            state[host] = current_ips

    if changed_any:
        save_state(state_path, state)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
