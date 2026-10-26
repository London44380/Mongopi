#!/usr/bin/env python3
"""
MongoPi - MongoDB no-auth exposure checker for authorized pentest labs.

Scope by design:
  - Only ever touches hosts YOU explicitly list (--targets / --targets-file).
  - No internet-wide / auto-discovery scanning mode.
  - Requires --authorized to actually connect (a deliberate speed bump).
  - Reports EXPOSURE (auth required or not, db/collection names, doc counts)
    as evidence for a pentest report. It does NOT bulk-download documents -
    use a targeted follow-up query yourself if you need a specific sample
    for your writeup.
  - Optional --proxy routes through exactly ONE configured SOCKS5/SOCKS4/HTTP
    proxy (e.g. an engagement jump host or VPN gateway) - not a rotating
    proxy list. This tool intentionally has no multi-proxy rotation, since
    that's an origin-hiding/evasion feature that doesn't fit a scanner
    scoped to targets you already have direct authorization to test.
"""

import argparse
import concurrent.futures
import json
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    from pymongo import MongoClient
    from pymongo.errors import OperationFailure, PyMongoError
except ImportError:
    sys.exit("Missing dependency: pip install -r requirements.txt")

try:
    import pyfiglet
except ImportError:
    pyfiglet = None

try:
    import socks  # PySocks
except ImportError:
    socks = None

ECO_GREEN = "\033[38;5;34m"
TEAL = "\033[38;5;30m"
MARINE_BLUE = "\033[38;5;27m"
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[38;5;196m"
YELLOW = "\033[38;5;220m"
GREY = "\033[38;5;244m"

DEFAULT_PORT = 27017
DEFAULT_TIMEOUT_MS = 6000
SYSTEM_DBS = {"admin", "local", "config"}

PROXY_SCHEMES = {
    "socks5": "SOCKS5",
    "socks4": "SOCKS4",
    "http": "HTTP",
}


class _ProxiedSocket(socks.socksocket if socks else object):
    """PySocks rejects the SOCK_CLOEXEC flag that Python's socket layer sets
    on created sockets (type ends up as SOCK_STREAM|SOCK_CLOEXEC = 524289,
    and socksocket's strict type check only accepts bare SOCK_STREAM/
    SOCK_DGRAM). Strip that flag before handing off to socksocket so pymongo
    can create sockets through the proxy without crashing."""

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, *args, **kwargs):
        cloexec = getattr(socket, "SOCK_CLOEXEC", 0)
        if cloexec and (type & cloexec):
            type &= ~cloexec
        super().__init__(family, type, proto, *args, **kwargs)


def configure_proxy(proxy_url: str) -> str:
    """Route ALL subsequent connections in this process through one proxy
    (jump host / VPN gateway), by monkeypatching the default socket class.
    Deliberately single-proxy: no list, no rotation, no failover between
    proxies - that pattern belongs to scanner-origin-hiding tools, not this
    one."""
    if socks is None:
        sys.exit("PySocks is required for --proxy: pip install -r requirements.txt")

    parsed = urlparse(proxy_url)
    scheme = parsed.scheme.lower()
    if scheme not in PROXY_SCHEMES:
        sys.exit(f"Unsupported --proxy scheme '{scheme}'. Use socks5://, socks4://, or http://")
    if not parsed.hostname or not parsed.port:
        sys.exit("--proxy must be scheme://host:port (e.g. socks5://10.0.0.1:1080)")

    proxy_type = getattr(socks, PROXY_SCHEMES[scheme])
    socks.set_default_proxy(
        proxy_type,
        parsed.hostname,
        parsed.port,
        username=parsed.username,
        password=parsed.password,
    )
    socket.socket = _ProxiedSocket
    return f"{PROXY_SCHEMES[scheme]} {parsed.hostname}:{parsed.port}"


def banner() -> str:
    if pyfiglet is not None:
        try:
            text = pyfiglet.figlet_format("MONGOPI", font="block")
        except Exception:
            text = pyfiglet.figlet_format("MONGOPI")
    else:
        text = (
            " __  __  _____  _  _   _____  _____  _____  _____\n"
            "|  \\/  ||  _  || || | | ____|/  _  \\|  _  ||_   _|\n"
            "| |\\/| || |_| || || | | |__  | |_| || |_| |  | |\n"
            "| |  | ||  _  || || | |  __| |  _  ||  _  |  | |\n"
            "| |  | || | | || || | | |    | | | || | | |  | |\n"
            "|_|  |_||_| |_||_||_| |_|    |_| |_||_| |_|  |_|\n"
        )
    lines = [l for l in text.split("\n") if l.strip()]
    if not lines:
        return ""
    gradient = [ECO_GREEN, ECO_GREEN, TEAL, TEAL, MARINE_BLUE, MARINE_BLUE]
    out = []
    for i, line in enumerate(lines):
        idx = int(i / max(1, len(lines) - 1) * (len(gradient) - 1))
        out.append(f"{gradient[idx]}{BOLD}{line}{RESET}")
    out.append(f"{MARINE_BLUE}{'MongoDB no-auth exposure checker — authorized lab use only':^60}{RESET}")
    return "\n".join(out)


def parse_target(raw: str, default_port: int):
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return None
    if ":" in raw and not raw.startswith("["):
        host, _, port_s = raw.rpartition(":")
        try:
            return host, int(port_s)
        except ValueError:
            return raw, default_port
    return raw, default_port


def load_targets(args) -> list:
    targets = []
    if args.targets:
        for chunk in args.targets.split(","):
            t = parse_target(chunk, args.port)
            if t:
                targets.append(t)
    if args.targets_file:
        for line in Path(args.targets_file).read_text().splitlines():
            t = parse_target(line, args.port)
            if t:
                targets.append(t)
    seen, unique = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def get_version(client: MongoClient):
    """buildInfo does not require auth on most MongoDB builds, even when
    other commands do, so this can often succeed even behind auth."""
    try:
        info = client.admin.command("buildInfo")
        return info.get("version")
    except PyMongoError:
        return None


def check_target(host: str, port: int, timeout_ms: int, include_system_dbs: bool, retries: int = 1,
                  use_tls: bool = False, tls_insecure: bool = False) -> dict:
    result = {
        "host": host,
        "port": port,
        "status": "unreachable",
        "mongodb_detected": False,
        "version": None,
        "auth_required": None,
        "databases": [],
        "error": None,
    }

    client_kwargs = dict(
        serverSelectionTimeoutMS=timeout_ms,
        connectTimeoutMS=timeout_ms,
        socketTimeoutMS=timeout_ms,
        # Skip replica-set topology discovery: a standalone/lab mongod
        # with no replica set configured can otherwise stall here
        # until serverSelectionTimeoutMS expires, reporting as
        # "unreachable" even though the port is open and answering.
        directConnection=True,
    )
    if use_tls:
        client_kwargs["tls"] = True
        if tls_insecure:
            client_kwargs["tlsAllowInvalidCertificates"] = True

    client = None
    last_error = None
    for attempt in range(retries + 1):
        try:
            client = MongoClient(host, port, **client_kwargs)
            client.admin.command("ping")
            last_error = None
            break
        except OperationFailure:
            # Server answered the Mongo wire protocol but rejected the
            # command for auth reasons - that IS a positive MongoDB
            # detection, just an auth-protected one.
            result["status"] = "reachable"
            result["mongodb_detected"] = True
            result["auth_required"] = True
            result["version"] = get_version(client)
            return result
        except PyMongoError as e:
            last_error = e
            continue

    if last_error is not None:
        result["error"] = f"{type(last_error).__name__}: {last_error}"
        return result

    result["status"] = "reachable"
    result["mongodb_detected"] = True
    result["version"] = get_version(client)
    try:
        db_names = client.list_database_names()
        result["auth_required"] = False
    except OperationFailure:
        result["auth_required"] = True
        return result

    for db_name in db_names:
        if not include_system_dbs and db_name in SYSTEM_DBS:
            continue
        db_info = {"name": db_name, "collections": []}
        try:
            db = client[db_name]
            for coll_name in db.list_collection_names():
                try:
                    count = db[coll_name].estimated_document_count()
                except PyMongoError:
                    count = None
                db_info["collections"].append({"name": coll_name, "approx_docs": count})
        except OperationFailure:
            db_info["error"] = "listCollections denied"
        result["databases"].append(db_info)

    return result


def unreachable_hint(error: str) -> str:
    if not error:
        return ""
    e = error.lower()
    if "connection refused" in e:
        return "port closed / nothing listening"
    if "no route to host" in e:
        return "network routing/firewall issue"
    if "no servers found" in e or "timed out" in e or "timeout" in e:
        return "TCP likely open but no valid Mongo handshake - check TLS requirement, wrong port/service, or a firewall silently dropping packets (verify with: nc -zv / nmap -sV)"
    if "name or service not known" in e or "getaddrinfo" in e:
        return "DNS resolution failed - check the hostname"
    return ""


def render_result(r: dict) -> str:
    target = f"{r['host']}:{r['port']}"
    if r["status"] == "unreachable":
        hint = unreachable_hint(r["error"] or "")
        hint_text = f"\n      {YELLOW}hint: {hint}{RESET}" if hint else ""
        return f"  {GREY}{target:<30}{RESET} {GREY}unreachable ({r['error']}){RESET}{hint_text}"

    version_tag = f" [v{r['version']}]" if r.get("version") else " [version hidden]"

    if r["auth_required"]:
        return f"  {target:<30} {ECO_GREEN}auth required - OK{RESET}{TEAL}{version_tag}{RESET}"

    lines = [f"  {target:<30} {RED}{BOLD}NO AUTH - EXPOSED{RESET}{TEAL}{version_tag}{RESET}"]
    for db in r["databases"]:
        coll_summary = ", ".join(
            f"{c['name']} (~{c['approx_docs']} docs)" for c in db["collections"]
        ) or "(no collections)"
        lines.append(f"      {YELLOW}db={db['name']}{RESET}: {coll_summary}")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="MongoPi - MongoDB no-auth exposure checker for authorized pentest labs."
    )
    parser.add_argument("--targets", help="Comma-separated host[:port] list")
    parser.add_argument("--targets-file", help="File with one host[:port] per line")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Default port (default {DEFAULT_PORT})")
    parser.add_argument("--timeout-ms", type=int, default=DEFAULT_TIMEOUT_MS, help="Connection timeout in ms")
    parser.add_argument("--retries", type=int, default=1, help="Extra connection attempts before marking unreachable")
    parser.add_argument("--workers", type=int, default=5, help="Concurrent connections")
    parser.add_argument("--include-system-dbs", action="store_true", help="Also enumerate admin/local/config")
    parser.add_argument("--json-report", help="Write full JSON results to this path")
    parser.add_argument("--tls", action="store_true", help="Connect using TLS (try this if you get 'No servers found yet')")
    parser.add_argument("--tls-insecure", action="store_true", help="With --tls: skip certificate validation (lab self-signed certs)")
    parser.add_argument(
        "--proxy",
        help="Route through ONE proxy (jump host/VPN gateway): socks5://[user:pass@]host:port, "
             "socks4://host:port, or http://host:port. Not a list - single proxy only.",
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        required=True,
        help="Required: confirms you have explicit authorization to test every listed target",
    )
    args = parser.parse_args()

    print(banner())
    print()

    if args.proxy:
        proxy_desc = configure_proxy(args.proxy)
        print(f"{MARINE_BLUE}Routing through proxy: {proxy_desc}{RESET}\n")

    targets = load_targets(args)
    if not targets:
        sys.exit("No targets given. Use --targets or --targets-file.")

    print(f"{MARINE_BLUE}Scanning {len(targets)} authorized target(s)...{RESET}\n")

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {
            pool.submit(check_target, host, port, args.timeout_ms, args.include_system_dbs, args.retries,
                        args.tls, args.tls_insecure): (host, port)
            for host, port in targets
        }
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            results.append(r)
            print(render_result(r))

    exposed = [r for r in results if r.get("auth_required") is False]
    detected = [r for r in results if r.get("mongodb_detected")]
    print()
    print(f"{BOLD}Summary:{RESET} {len(results)} scanned, "
          f"{MARINE_BLUE}{len(detected)} MongoDB detected{RESET}, "
          f"{ECO_GREEN}{sum(1 for r in results if r['auth_required'])} auth-protected{RESET}, "
          f"{RED}{len(exposed)} exposed (no auth){RESET}, "
          f"{GREY}{sum(1 for r in results if r['status'] == 'unreachable')} unreachable{RESET}")
    if detected:
        print(f"\n{BOLD}Detected versions:{RESET}")
        for r in detected:
            v = r.get("version") or "hidden"
            print(f"  {r['host']}:{r['port']} -> {v}")

    if args.json_report:
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "targets_scanned": len(results),
            "results": results,
        }
        Path(args.json_report).write_text(json.dumps(report, indent=2, default=str))
        print(f"\nJSON report written to {args.json_report}")


if __name__ == "__main__":
    main()
