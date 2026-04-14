#!/usr/bin/env python3
import argparse
import datetime
import json
import os
import re
import shlex
import subprocess

ALLOWED_TOOLS = {
    "nuclei",
    "nikto",
    "sqlmap",
    "nmap",
    "ffuf",
    "gobuster",
    "wfuzz",
    "whatweb",
    "wafw00f",
    "testssl.sh",
    "hydra",
    "medusa",
    "wpscan",
    "dirb",
    "dirbuster",
}

_UNSAFE_ARG_RE = re.compile(r"[;&|`$><!\\\n\r]")


def is_allowed_tool(tool):
    """Return True only if the tool basename is in the allowlist."""
    return os.path.basename(tool) in ALLOWED_TOOLS


def sanitize_extra_args(extra):
    """Split extra into tokens and reject any containing shell metacharacters."""
    if not extra:
        return []
    tokens = shlex.split(extra)
    for token in tokens:
        if _UNSAFE_ARG_RE.search(token):
            raise ValueError(f"Unsafe character in argument: {token!r}")
    return tokens


def now():
    return datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")


def load_scope(path):
    with open(path) as f:
        return json.load(f)


def _normalize_host(value):
    value = value.strip().rstrip(".").lower()
    if value.startswith("[") and "]" in value:
        return value[1 : value.index("]")]
    if ":" in value and value.count(":") == 1:
        host, port = value.rsplit(":", 1)
        if port.isdigit():
            return host
    return value


def ensure_in_scope(target, scope):
    normalized_target = _normalize_host(target)
    allowed = [
        normalized
        for normalized in (_normalize_host(host) for host in scope.get("allowed_hosts", []))
        if normalized
    ]
    if not any(
        normalized_target == host or normalized_target.endswith("." + host)
        for host in allowed
    ):
        raise Exception(f"Target {target} not in allowed scope")


def run_cmd(cmd, log_file):
    argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
    with open(log_file, "a") as f:
        f.write(f"\n$ {' '.join(argv)}\n")
        p = subprocess.Popen(
            argv, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        for line in p.stdout:
            decoded = line.decode()
            print(decoded, end="")
            f.write(decoded)


def latest_run(base, target):
    target_dir = os.path.join(base, target)
    runs = sorted(os.listdir(target_dir))
    return os.path.join(target_dir, runs[-1])


def init(args):
    scope = load_scope(args.scope)
    ensure_in_scope(args.target, scope)
    run_id = now()
    run_path = os.path.join(args.base, args.target, run_id)
    os.makedirs(run_path, exist_ok=True)
    with open(os.path.join(run_path, "manifest.json"), "w") as f:
        json.dump({"target": args.target, "run_id": run_id}, f, indent=2)
    print(f"[+] Run initialized: {run_path}")


def recon(args):
    run_path = latest_run(args.base, args.target)
    log = os.path.join(run_path, "recon.log")
    run_cmd(f"subfinder -d {args.target} -silent", log)
    run_cmd("httpx -silent", log)


def map_stage(args):
    run_path = latest_run(args.base, args.target)
    log = os.path.join(run_path, "map.log")
    run_cmd(f"gau {args.target}", log)


def attack(args):
    run_path = latest_run(args.base, args.target)
    log = os.path.join(run_path, "attack.log")
    if args.tag == "disruptive" and not args.allow:
        raise Exception("Disruptive actions not allowed")
    if not is_allowed_tool(args.tool):
        raise ValueError(
            f"Tool {args.tool!r} is not permitted. "
            f"Allowed tools: {', '.join(sorted(ALLOWED_TOOLS))}"
        )
    extra_args = sanitize_extra_args(args.extra)
    run_cmd([args.tool, *extra_args], log)


def report(args):
    run_path = latest_run(args.base, args.target)
    report = os.path.join(run_path, "REPORT.md")
    with open(report, "w") as f:
        f.write(f"# Report for {args.target}\n")
    print(f"[+] Report generated: {report}")


parser = argparse.ArgumentParser()
sub = parser.add_subparsers()

p = sub.add_parser("init")
p.add_argument("--target", required=True)
p.add_argument("--scope", required=True)
p.add_argument("--base", default="runs")
p.set_defaults(func=init)

p = sub.add_parser("recon")
p.add_argument("--target", required=True)
p.add_argument("--base", default="runs")
p.set_defaults(func=recon)

p = sub.add_parser("map")
p.add_argument("--target", required=True)
p.add_argument("--base", default="runs")
p.set_defaults(func=map_stage)

p = sub.add_parser("attack")
p.add_argument("--target", required=True)
p.add_argument("--tool", required=True)
p.add_argument("--extra", default="")
p.add_argument("--tag", default="safe")
p.add_argument("--allow", action="store_true")
p.add_argument("--base", default="runs")
p.set_defaults(func=attack)

p = sub.add_parser("report")
p.add_argument("--target", required=True)
p.add_argument("--base", default="runs")
p.set_defaults(func=report)

args = parser.parse_args()
if hasattr(args, "func"):
    args.func(args)