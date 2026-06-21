import argparse
import sys

from rich import box
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

from .models import Finding
from .pipeline import run_scan
from .policy_loader import load_policies

console = Console()

SEVERITY_COLOR = {"high": "red", "medium": "yellow", "low": "cyan"}
SEVERITY_ORDER = ["high", "medium", "low"]


def _render_finding(finding: Finding, severity: str) -> Panel:
    color = SEVERITY_COLOR[severity]
    content = (
        f"[bold]  {escape(finding.line_content.strip())}[/]\n\n"
        f"  [bold {color}]✗[/]  {escape(finding.explanation)}\n"
        f"  [bold green]→[/]  [dim]{escape(finding.suggested_fix)}[/]"
    )
    return Panel(
        content,
        title=f"[bold]{escape(finding.file_path)}[/][dim]:{finding.line_number}[/]",
        title_align="left",
        border_style=color,
        box=box.ROUNDED,
        padding=(1, 2),
    )


def _scan(args: argparse.Namespace) -> None:
    console.print()
    console.rule("[bold white]RedHanded[/]  [dim]policy drift scan[/]")
    console.print()

    report = run_scan(args.repo_path, args.policies)

    policies = load_policies(args.policies)
    policy_map = {p.id: p for p in policies}

    grouped: dict[str, list[Finding]] = {"high": [], "medium": [], "low": []}
    for finding in report.findings:
        policy = policy_map.get(finding.policy_id)
        if policy:
            grouped[policy.severity].append(finding)

    if not report.findings:
        console.print()
        console.print("[bold green]  ✓  No violations found.[/]", justify="center")
        console.print()
    else:
        for severity in SEVERITY_ORDER:
            findings = grouped[severity]
            if not findings:
                continue
            color = SEVERITY_COLOR[severity]
            count = len(findings)
            console.rule(
                f"[bold {color}]{severity.upper()}[/]  "
                f"[dim]{count} finding{'s' if count != 1 else ''}[/]"
            )
            console.print()
            for finding in findings:
                console.print(_render_finding(finding, severity))
            console.print()

    total = len(report.findings)
    summary = Text(justify="center")
    summary.append(f"{report.files_scanned}", style="bold")
    summary.append(" files scanned · ", style="dim")
    summary.append(f"{report.policies_checked}", style="bold")
    summary.append(" policies checked · ", style="dim")
    if total:
        summary.append(f"{total} violation{'s' if total != 1 else ''} found", style="bold red")
    else:
        summary.append("clean", style="bold green")

    console.rule()
    console.print(summary)
    console.print()

    sys.exit(1 if report.findings else 0)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="policydrift",
        description="Find where code violates plain-English policies.",
    )
    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="Scan a repo for policy violations")
    scan_parser.add_argument("repo_path", help="Path to the repository to scan")
    scan_parser.add_argument(
        "--policies", required=True, metavar="FILE", help="Path to policies YAML"
    )

    args = parser.parse_args()
    if args.command == "scan":
        _scan(args)
    else:
        parser.print_help()
