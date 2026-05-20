#!/usr/bin/env python3
import os, json, argparse, subprocess, datetime, shlex

ALLOWED_TOOLS = {"nuclei", "sqlmap", "ffuf", "nikto", "nmap"}


def is_allowed_tool(tool):
    return os.path.basename(tool) == tool and tool in ALLOWED_TOOLS


def now():
    return datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")

def load_scope(path):
    with open(path) as f:
        return json.load(f)

def ensure_in_scope(target, scope):
    allowed = scope.get("allowed_hosts", [])
    if not any(target.endswith(a) for a in allowed):
        raise Exception(f"Target {target} not in allowed scope")

def run_cmd(cmd, log_file):
    with open(log_file, "a") as f:
        f.write(f"\n$ {shlex.join(cmd)}\n")
        p = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
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
    run_cmd(["subfinder", "-d", args.target, "-silent"], log)
    run_cmd(["httpx", "-silent"], log)

def map_stage(args):
    run_path = latest_run(args.base, args.target)
    log = os.path.join(run_path, "map.log")
    run_cmd(["gau", args.target], log)

def attack(args):
    run_path = latest_run(args.base, args.target)
    log = os.path.join(run_path, "attack.log")
    if args.tag == "disruptive" and not args.allow:
        raise Exception("Disruptive actions not allowed")
    if not is_allowed_tool(args.tool):
        raise Exception(f"Tool {args.tool!r} is not in the allowed list")
    run_cmd([args.tool] + shlex.split(args.extra), log)

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
