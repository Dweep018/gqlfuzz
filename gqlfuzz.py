#!/usr/bin/env python3
"""
gqlfuzz — GraphQL Unbounded Argument DoS Scanner
Finds Int arguments in a GraphQL schema and fuzzes them with large values,
measuring response time and size degradation.
"""

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime, timezone

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import box
from rich.text import Text

console = Console()

BANNER = """[bold red]
  ██████  ██████  ██      ███████ ██    ██ ███████ ███████ 
 ██       ██   ██ ██      ██      ██    ██    ███     ███  
 ██   ███ ██   ██ ██      █████   ██    ██   ███     ███   
 ██    ██ ██   ██ ██      ██      ██    ██  ███     ███    
  ██████  ██████  ███████ ██       ██████  ███████ ███████ 
[/bold red][dim]  GraphQL Unbounded Argument DoS Scanner[/dim]
"""

# Argument names that are almost always backed by a DB LIMIT clause
LIMIT_ARG_NAMES = {
    "limit", "first", "last", "count", "size", "top",
    "pageSize", "page_size", "perPage", "per_page",
    "take", "fetch", "rows", "max", "maxResults",
    "max_results", "num", "number", "n",
}

# Fuzz values — escalating from sane to extreme
FUZZ_VALUES = [100, 10_000, 1_000_000, 999_999_999]

# How many times slower does a response need to be to flag as vulnerable
SLOWDOWN_THRESHOLD = 3.0  # 3x baseline = flag it

# Introspection query to discover all fields and their Int arguments
INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    types {
      name
      kind
      fields {
        name
        args {
          name
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
        type {
          name
          kind
          fields {
            name
            args {
              name
              type {
                name
                kind
                ofType { name kind }
              }
            }
          }
        }
      }
    }
  }
}
"""

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim white",
}

SEVERITY_ICONS = {
    "CRITICAL": "💀",
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "ℹ️ ",
}


def is_int_type(arg_type: dict) -> bool:
    """Check if an argument type resolves to Int."""
    if not arg_type:
        return False
    name = arg_type.get("name", "") or ""
    if name in ("Int", "BigInt", "Long"):
        return True
    of_type = arg_type.get("ofType")
    if of_type:
        return is_int_type(of_type)
    return False


def is_limit_arg(arg_name: str) -> bool:
    """Check if argument name looks like a limit/count parameter."""
    lower = arg_name.lower()
    return any(kw in lower for kw in [
        "limit", "first", "last", "count", "size", "top",
        "page_size", "pagesize", "perpage", "per_page",
        "take", "fetch", "rows", "max", "num", "number"
    ])


def extract_int_args(schema: dict) -> list[dict]:
    """
    Walk the schema and find all fields that have Int arguments.
    Returns list of {query_type, field, arg, is_limit_like}
    """
    targets = []
    types = schema.get("types", [])
    query_type_name = schema.get("queryType", {}).get("name", "Query")

    for t in types:
        if t.get("name") != query_type_name:
            continue
        if not t.get("fields"):
            continue

        for field in t["fields"]:
            field_name = field["name"]
            for arg in field.get("args", []):
                if is_int_type(arg.get("type")):
                    targets.append({
                        "field": field_name,
                        "arg": arg["name"],
                        "is_limit_like": is_limit_arg(arg["name"]),
                        "subfields": _get_subfields(field),
                    })

            # Also check nested fields (e.g. instruments -> price_bars(limit))
            field_type = field.get("type", {})
            nested_fields = field_type.get("fields") or []
            for nfield in nested_fields:
                for arg in nfield.get("args", []):
                    if is_int_type(arg.get("type")):
                        targets.append({
                            "field": field_name,
                            "nested_field": nfield["name"],
                            "arg": arg["name"],
                            "is_limit_like": is_limit_arg(arg["name"]),
                            "subfields": [],
                        })

    return targets


def _get_subfields(field: dict) -> list[str]:
    """Get scalar subfield names for building a minimal query."""
    field_type = field.get("type", {})
    fields = field_type.get("fields") or []
    scalar_names = []
    for f in fields:
        type_name = (f.get("type") or {}).get("name") or ""
        if type_name in ("String", "Int", "Float", "Boolean", "ID", ""):
            scalar_names.append(f["name"])
        if len(scalar_names) >= 3:
            break
    return scalar_names or ["__typename"]


def build_query(target: dict, value: int) -> str:
    """Build a minimal GraphQL query for a given target and fuzz value."""
    field = target["field"]
    arg = target["arg"]
    subfields = target.get("subfields") or ["__typename"]
    nested = target.get("nested_field")

    subfield_str = " ".join(subfields[:3])

    if nested:
        return f'{{ {field} {{ {nested}({arg}: {value}) {{ __typename }} }} }}'
    else:
        return f'{{ {field}({arg}: {value}) {{ {subfield_str} }} }}'


async def get_baseline(client: httpx.AsyncClient, target_url: str, query: str) -> dict:
    """Get baseline response with value=1."""
    try:
        t0 = time.monotonic()
        resp = await client.post(target_url, json={"query": query})
        elapsed = time.monotonic() - t0
        return {
            "time": elapsed,
            "size": len(resp.content),
            "status": resp.status_code,
            "ok": resp.status_code == 200 and "errors" not in resp.text,
        }
    except Exception as e:
        return {"time": None, "size": 0, "status": 0, "ok": False, "error": str(e)}


async def fuzz_argument(
    client: httpx.AsyncClient,
    target_url: str,
    target: dict,
) -> dict | None:
    """
    Fuzz a single argument with escalating values.
    Returns a finding dict if vulnerable, else None.
    """
    field = target["field"]
    arg = target["arg"]
    nested = target.get("nested_field", "")
    label = f"{field}.{nested + '.' if nested else ''}{arg}"

    # Baseline with value=1
    baseline_query = build_query(target, 1)
    baseline = await get_baseline(client, target_url, baseline_query)

    if not baseline["ok"]:
        return None  # Field doesn't work or needs auth — skip

    baseline_time = baseline["time"]
    baseline_size = baseline["size"]

    worst = {"value": None, "time": None, "size": None, "slowdown": 0, "size_growth": 0}

    for value in FUZZ_VALUES:
        query = build_query(target, value)
        try:
            t0 = time.monotonic()
            resp = await client.post(target_url, json={"query": query})
            elapsed = time.monotonic() - t0
            size = len(resp.content)

            slowdown = elapsed / baseline_time if baseline_time > 0 else 1
            size_growth = size / baseline_size if baseline_size > 0 else 1

            if slowdown > worst["slowdown"]:
                worst = {
                    "value": value,
                    "time": elapsed,
                    "size": size,
                    "slowdown": slowdown,
                    "size_growth": size_growth,
                    "status": resp.status_code,
                }

            # Stop early if already confirmed critical
            if slowdown >= 10:
                break

        except httpx.TimeoutException:
            # Timeout itself is a strong DoS signal
            worst = {
                "value": value,
                "time": client.timeout.read,
                "size": 0,
                "slowdown": 99,
                "size_growth": 0,
                "status": 0,
                "timed_out": True,
            }
            break
        except Exception:
            continue

    if worst["slowdown"] < SLOWDOWN_THRESHOLD and worst["size_growth"] < 10:
        return None  # Not vulnerable

    # Determine severity based on slowdown factor
    slowdown = worst["slowdown"]
    if worst.get("timed_out") or slowdown >= 15:
        severity = "CRITICAL"
    elif slowdown >= 8:
        severity = "HIGH"
    elif slowdown >= SLOWDOWN_THRESHOLD:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "field": label,
        "arg": arg,
        "is_limit_like": target["is_limit_like"],
        "severity": severity,
        "baseline_time_ms": round(baseline_time * 1000),
        "baseline_size_bytes": baseline_size,
        "worst_value": worst["value"],
        "worst_time_ms": round(worst["time"] * 1000) if worst["time"] else None,
        "worst_size_bytes": worst["size"],
        "slowdown_factor": round(slowdown, 1),
        "size_growth_factor": round(worst["size_growth"], 1),
        "timed_out": worst.get("timed_out", False),
        "query_used": build_query(target, worst["value"]),
        "recommendation": (
            f"Enforce a hard server-side cap on `{arg}` (e.g. max 500). "
            "Never trust the client to send a reasonable value. "
            "Add pagination and reject requests exceeding the cap with HTTP 400."
        ),
    }


def print_finding(f: dict):
    sev = f["severity"]
    color = SEVERITY_COLORS[sev]
    icon = SEVERITY_ICONS[sev]

    console.print(Text.assemble(
        (f"{icon} [{sev}] ", color),
        (f["field"], "bold white"),
    ))

    timed_out_note = " [bold red](TIMED OUT)[/bold red]" if f["timed_out"] else ""
    limit_note = " [dim](limit-like arg)[/dim]" if f["is_limit_like"] else ""

    console.print(f"  [dim]Argument:[/dim]     [cyan]{f['arg']}[/cyan]{limit_note}")
    console.print(
        f"  [dim]Baseline:[/dim]     {f['baseline_time_ms']}ms  /  {f['baseline_size_bytes']:,} bytes"
    )
    console.print(
        f"  [dim]Worst:[/dim]        value=[bold]{f['worst_value']:,}[/bold]  →  "
        f"{f['worst_time_ms']}ms  /  {f['worst_size_bytes']:,} bytes{timed_out_note}"
    )
    console.print(
        f"  [dim]Slowdown:[/dim]     [bold {color}]{f['slowdown_factor']}x[/bold {color}]  "
        f"  Size growth: {f['size_growth_factor']}x"
    )
    console.print(f"  [dim]Fix:[/dim]          [italic]{f['recommendation']}[/italic]")
    console.print(f"  [dim]Query:[/dim]        [dim]{f['query_used']}[/dim]")
    console.print()


def print_summary(findings: list, target: str, elapsed: float, total_args: int):
    console.print(Rule("[bold]Scan Summary[/bold]"))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    table = Table(box=box.ROUNDED, header_style="bold dim")
    table.add_column("Target", style="cyan")
    table.add_column("Args Tested", justify="center")
    table.add_column("Vulnerable", justify="center")
    table.add_column("Critical", style="bold red", justify="center")
    table.add_column("High", style="red", justify="center")
    table.add_column("Medium", style="yellow", justify="center")
    table.add_column("Duration", justify="right")

    table.add_row(
        target,
        str(total_args),
        str(len(findings)),
        str(counts.get("CRITICAL", 0)),
        str(counts.get("HIGH", 0)),
        str(counts.get("MEDIUM", 0)),
        f"{elapsed:.1f}s",
    )
    console.print(table)


def generate_json_report(target: str, findings: list, elapsed: float, total_args: int) -> dict:
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(findings, key=lambda f: severity_order.get(f["severity"], 9))

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    overall = "NONE"
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if counts[sev] > 0:
            overall = sev
            break

    return {
        "scanner": "gqlfuzz — GraphQL Unbounded Argument DoS Scanner",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scan_duration_seconds": round(elapsed, 2),
        "total_args_tested": total_args,
        "summary": {
            "overall_risk": overall,
            "vulnerable_args": len(findings),
            "by_severity": counts,
        },
        "findings": sorted_findings,
    }


async def main():
    parser = argparse.ArgumentParser(
        prog="gqlfuzz",
        description="GraphQL Unbounded Argument DoS Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gqlfuzz.py https://<target>/graphql
  python gqlfuzz.py https://api.example.com/graphql -t mytoken
  python gqlfuzz.py https://api.example.com/graphql -o report.json
  python gqlfuzz.py https://api.example.com/graphql --timeout 30 --threshold 2.0
        """,
    )
    parser.add_argument("target", help="GraphQL endpoint URL")
    parser.add_argument("-t", "--token", help="Bearer token for Authorization header")
    parser.add_argument("-H", "--header", action="append", metavar="KEY:VALUE", help="Extra headers")
    parser.add_argument("--timeout", type=int, default=20, help="Request timeout in seconds (default: 20)")
    parser.add_argument("--threshold", type=float, default=SLOWDOWN_THRESHOLD,
                        help=f"Slowdown multiplier to flag as vulnerable (default: {SLOWDOWN_THRESHOLD})")
    parser.add_argument("-o", "--output", help="Save JSON report to file")
    parser.add_argument("--all-ints", action="store_true",
                        help="Fuzz ALL Int args, not just limit-like ones (slower)")
    parser.add_argument("--no-banner", action="store_true")

    args = parser.parse_args()

    if not args.no_banner:
        console.print(BANNER)

    headers = {"Content-Type": "application/json"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    for h in args.header or []:
        k, _, v = h.partition(":")
        headers[k.strip()] = v.strip()

    console.print(Panel(
        f"[bold white]Target:[/bold white]    [cyan]{args.target}[/cyan]\n"
        f"[bold white]Threshold:[/bold white] {args.threshold}x slowdown\n"
        f"[bold white]Timeout:[/bold white]   {args.timeout}s per request\n"
        f"[bold white]Fuzz all:[/bold white]  {'Yes' if args.all_ints else 'No — limit-like args only'}",
        title="[bold]Scan Configuration[/bold]",
        border_style="dim",
    ))

    async with httpx.AsyncClient(headers=headers, timeout=args.timeout, verify=False) as client:

        # Step 1: Introspect
        console.print("\n[bold dim]▶ Step 1:[/bold dim] Introspecting schema...")
        try:
            resp = await client.post(args.target, json={"query": INTROSPECTION_QUERY})
            data = resp.json()
            schema = data.get("data", {}).get("__schema", {})
            if not schema:
                console.print("[red]✗ Introspection failed or is disabled.[/red]")
                console.print("[dim]Try running with a valid token (-t) or check if the endpoint is correct.[/dim]")
                sys.exit(1)
        except Exception as e:
            console.print(f"[red]✗ Could not reach endpoint: {e}[/red]")
            sys.exit(1)

        # Step 2: Extract Int arguments
        all_targets = extract_int_args(schema)
        if args.all_ints:
            targets = all_targets
        else:
            targets = [t for t in all_targets if t["is_limit_like"]]

        if not targets:
            console.print(f"[yellow]⚠ No {'limit-like ' if not args.all_ints else ''}Int arguments found.[/yellow]")
            console.print("[dim]Try --all-ints to fuzz every Int argument in the schema.[/dim]")
            sys.exit(0)

        console.print(f"[green]✓ Found {len(all_targets)} Int args total — fuzzing {len(targets)}[/green]")
        if not args.all_ints:
            console.print(f"[dim]  (limit/count/size-like args only — use --all-ints for all)[/dim]")

        # Step 3: Fuzz each argument
        console.print(f"\n[bold dim]▶ Step 2:[/bold dim] Fuzzing {len(targets)} arguments...\n")

        start = time.monotonic()
        findings = []

        for i, target in enumerate(targets):
            label = f"{target['field']}.{target.get('nested_field', '') + '.' if target.get('nested_field') else ''}{target['arg']}"
            console.print(f"[dim]  [{i+1}/{len(targets)}] Testing {label}...[/dim]", end="\r")

            finding = await fuzz_argument(client, args.target, target)
            if finding:
                console.print(" " * 80, end="\r")  # clear the progress line
                print_finding(finding)
                findings.append(finding)

        elapsed = time.monotonic() - start
        console.print(" " * 80, end="\r")  # clear last progress line

        print_summary(findings, args.target, elapsed, len(targets))

        if args.output:
            report = generate_json_report(args.target, findings, elapsed, len(targets))
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
            console.print(f"\n[green]✓ JSON report saved to:[/green] [bold]{args.output}[/bold]")

        severities = {f["severity"] for f in findings}
        if "CRITICAL" in severities:
            sys.exit(2)
        elif "HIGH" in severities:
            sys.exit(1)
        sys.exit(0)


if __name__ == "__main__":
    asyncio.run(main())
