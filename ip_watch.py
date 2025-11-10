#!/usr/bin/env python3
"""
Watch DNS A/AAAA answers for one or more hostnames and log when they change.

Usage:
  python3 ip_watch.py your-app.onrender.com
  python3 ip_watch.py your-app.onrender.com app.yourdomain.com
Options:
  --state-dir .state
  --log-file ip_changes.log
  --retries 2
  --timeout 3.0
"""
import argparse
import json
import os
import socket
import sys
import time
from datetime import datetime

def iso_now():
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def resolve_all(host, timeout, retries):
    """Return a sorted list of unique IPv4/IPv6 addresses for host."""
    ips = set()
    last_err = None
    for _ in range(retries + 1):
        try:
            # getaddrinfo respects system resolver, returns both A and AAAA
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP, timeout=timeout)
            for family, _, _, _, sockaddr in infos:
                ip = sockaddr[0]
                # Filter out link-local or weird entries, just in case
                if ":" in ip:  # IPv6
                    ips.add(ip)
                else:          # IPv4
                    ips.add(ip)
            return sorted(ips)
        except Exception as e:
            last_err = e
            time.sleep(0.3)
    raise last_err

def load_state(path):
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
    os.replace(tmp, path)

def log(line, log_file):
    os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def main():
    ap = argparse.ArgumentParser(description="Log when DNS answers change.")
    ap.add_argument("hostnames", nargs="+", help="Hostnames to watch")
    ap.add_argument("--state-dir", default=".state", help="Directory for state file")
    ap.add_argument("--log-file", default="ip_changes.log", help="Path to log file")
    ap.add_argument("--retries", type=int, default=2, help="DNS retry attempts")
    ap.add_argument("--timeout", type=float, default=3.0, help="Per-lookup timeout (seconds)")
    args = ap.parse_args()

    state_path = os.path.join(args.state_dir, "last_ips.json")
    state = load_state(state_path)
    changed_any = False
    exit_code = 0

    for host in args.hostnames:
        try:
            current_ips = resolve_all(host, args.timeout, args.retries)
        except Exception as e:
            log(json.dumps({
                "ts": iso_now(),
                "level": "error",
                "event": "dns_lookup_failed",
                "host": host,
                "error": str(e),
            }), args.log_file)
            exit_code = 2
            continue

        prev_ips = state.get(host, [])
        if sorted(prev_ips) != current_ips:
            changed_any = True
            log(json.dumps({
                "ts": iso_now(),
                "level": "info",
                "event": "ip_changed",
                "host": host,
                "before": prev_ips,
                "after": current_ips,
            }), args.log_file)
            state[host] = current_ips
        else:
            # Optional: uncomment to also log steady state snapshots
            # log(json.dumps({
            #     "ts": iso_now(),
            #     "level": "debug",
            #     "event": "no_change",
            #     "host": host,
            #     "ips": current_ips,
            # }), args.log_file)
            pass

    # persist state if anything changed
    if changed_any:
        save_state(state_path, state)

    sys.exit(exit_code)

if __name__ == "__main__":
    main()
