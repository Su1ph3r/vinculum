"""Console output formatter using rich library."""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from vinculum.correlation.engine import CorrelationResult
from vinculum.models.enums import Severity
from vinculum.models.finding import CorrelationGroup, UnifiedFinding


class ConsoleOutputFormatter:
    """Format correlation results for console display using rich."""

    SEVERITY_COLORS = {
        "critical": "bright_red",
        "high": "red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    SEVERITY_ICONS = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }

    def __init__(self, console: Console | None = None, verbose: bool = False):
        """
        Initialize the formatter.

        Args:
            console: Rich console instance
            verbose: Show detailed output
        """
        self.console = console or Console()
        self.verbose = verbose

    def print(self, result: CorrelationResult) -> None:
        """Print correlation results to console."""
        self._print_summary(result)
        self._print_findings_table(result)

        if self.verbose:
            self._print_group_details(result)

    def _print_summary(self, result: CorrelationResult) -> None:
        """Print summary statistics."""
        summary = Table(title="Correlation Summary", show_header=False, box=None)
        summary.add_column("Metric", style="bold")
        summary.add_column("Value", justify="right")

        if result.metadata.get("run_id"):
            summary.add_row("Run ID", result.metadata["run_id"])
        summary.add_row("Total Findings", str(result.original_count))
        summary.add_row("Unique Issues", str(result.unique_count))
        summary.add_row("Duplicates Removed", str(result.duplicate_count))
        summary.add_row(
            "Deduplication Rate", f"{result.dedup_rate:.1f}%"
        )
        summary.add_row(
            "Multi-Tool Detections", str(len(result.multi_tool_findings()))
        )

        self.console.print(Panel(summary, title="📊 Summary", border_style="blue"))
        self.console.print()

        # Severity breakdown
        self._print_severity_breakdown(result)

        # Tool breakdown
        self._print_tool_breakdown(result)

    def _print_severity_breakdown(self, result: CorrelationResult) -> None:
        """Print breakdown by severity."""
        by_severity = result.by_severity()

        table = Table(title="By Severity", show_header=True)
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")
        table.add_column("Bar")

        total = sum(by_severity.values()) or 1
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = by_severity.get(sev, 0)
            bar_width = int((count / total) * 30)
            bar = "█" * bar_width
            color = self.SEVERITY_COLORS.get(sev, "white")
            icon = self.SEVERITY_ICONS.get(sev, "")

            table.add_row(
                Text(f"{icon} {sev.upper()}", style=color),
                str(count),
                Text(bar, style=color),
            )

        self.console.print(table)
        self.console.print()

    def _print_tool_breakdown(self, result: CorrelationResult) -> None:
        """Print breakdown by tool."""
        by_tool = result.by_tool()

        table = Table(title="By Tool", show_header=True)
        table.add_column("Tool", style="bold")
        table.add_column("Findings", justify="right")

        for tool, count in sorted(by_tool.items(), key=lambda x: -x[1]):
            table.add_row(tool, str(count))

        self.console.print(table)
        self.console.print()

    def _print_findings_table(self, result: CorrelationResult) -> None:
        """Print findings table."""
        table = Table(title="Findings", show_header=True, expand=True)
        table.add_column("Sev", width=4, justify="center")
        table.add_column("Title", ratio=3)
        table.add_column("Location", ratio=2)
        table.add_column("Tools", width=15)
        table.add_column("CVEs", width=15)

        # Sort by severity (critical first)
        sorted_groups = sorted(
            result.groups,
            key=lambda g: Severity(g.max_severity).numeric,
            reverse=True,
        )

        for group in sorted_groups[:50]:  # Limit to 50 for display
            primary = group.primary_finding
            if not primary:
                continue

            sev = primary.severity
            icon = self.SEVERITY_ICONS.get(sev, "")
            color = self.SEVERITY_COLORS.get(sev, "white")

            # Title (truncated)
            title = primary.title[:50] + "..." if len(primary.title) > 50 else primary.title

            # Location
            loc = primary.location
            if loc.url:
                location = loc.url[:30] + "..." if len(loc.url) > 30 else loc.url
            elif loc.file_path:
                location = f"{loc.file_path}:{loc.line_start or ''}"
                if len(location) > 30:
                    location = "..." + location[-27:]
            elif loc.host:
                location = f"{loc.host}:{loc.port or ''}"
            else:
                location = "-"

            # Tools
            tools = ", ".join(sorted(group.tool_sources))

            # CVEs
            cves = ", ".join(sorted(group.all_cves)[:2])
            if len(group.all_cves) > 2:
                cves += f" +{len(group.all_cves) - 2}"

            table.add_row(
                Text(icon, style=color),
                Text(title, style=color),
                location,
                tools,
                cves or "-",
            )

        if len(result.groups) > 50:
            self.console.print(f"[dim]... and {len(result.groups) - 50} more findings[/dim]")

        self.console.print(table)

    def _print_group_details(self, result: CorrelationResult) -> None:
        """Print detailed group information (verbose mode)."""
        self.console.print("\n[bold]Detailed Findings:[/bold]\n")

        for group in result.groups[:20]:  # Limit for readability
            self._print_group(group)

    def _print_group(self, group: CorrelationGroup) -> None:
        """Print a single correlation group."""
        primary = group.primary_finding
        if not primary:
            return

        sev = primary.severity
        color = self.SEVERITY_COLORS.get(sev, "white")
        icon = self.SEVERITY_ICONS.get(sev, "")

        title = f"{icon} [{color}]{primary.title}[/{color}]"
        subtitle = f"[dim]Detected by {len(group.tool_sources)} tool(s): {', '.join(group.tool_sources)}[/dim]"

        content = []
        content.append(f"[bold]Severity:[/bold] [{color}]{sev.upper()}[/{color}]")

        if group.all_cves:
            content.append(f"[bold]CVEs:[/bold] {', '.join(group.all_cves)}")

        if primary.cwe_ids:
            content.append(f"[bold]CWEs:[/bold] {', '.join(primary.cwe_ids)}")

        if primary.description:
            desc = primary.short_description(200)
            content.append(f"\n[bold]Description:[/bold]\n{desc}")

        if primary.remediation:
            rem = primary.remediation[:200] + "..." if len(primary.remediation) > 200 else primary.remediation
            content.append(f"\n[bold]Remediation:[/bold]\n{rem}")

        panel = Panel(
            "\n".join(content),
            title=title,
            subtitle=subtitle,
            border_style=color,
        )
        self.console.print(panel)
        self.console.print()


def print_results(result: CorrelationResult, verbose: bool = False) -> None:
    """Convenience function to print results to console."""
    formatter = ConsoleOutputFormatter(verbose=verbose)
    formatter.print(result)
