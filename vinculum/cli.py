"""CLI interface for Vinculum - Security Finding Correlation Engine."""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn

from vinculum import __version__
from vinculum.config import VinculumConfig, load_config, merge_cli_with_config
from vinculum.correlation.ai_correlator import get_ai_correlator
from vinculum.correlation.engine import CorrelationEngine, CorrelationResult, correlate_findings
from vinculum.enrichment.cross_tool import CrossToolEnricher
from vinculum.enrichment.epss import EPSSEnricher
from vinculum.logging import setup_logging
from vinculum.models.finding import UnifiedFinding
from vinculum.output.ariadne_output import AriadneOutputFormatter
from vinculum.output.burrito_output import BurritoOutputFormatter
from vinculum.output.console_output import ConsoleOutputFormatter
from vinculum.output.json_output import JSONOutputFormatter
from vinculum.output.sarif_output import SARIFOutputFormatter
from vinculum.parsers.base import ParseError, ParserRegistry
from vinculum.parsers.ariadne import AriadneParser
from vinculum.parsers.ariadne_report import AriadneReportParser
from vinculum.parsers.burp import BurpParser
from vinculum.parsers.bypassburrito import BypassBurritoParser
from vinculum.parsers.cepheus import CepheusParser
from vinculum.parsers.checkov import CheckovParser
from vinculum.parsers.dependency_check import DependencyCheckParser
from vinculum.parsers.grype import GrypeParser
from vinculum.parsers.indago import IndagoParser
from vinculum.parsers.mobilicustos import MobilicustosParser
from vinculum.parsers.mobsf import MobSFParser
from vinculum.parsers.nessus import NessusParser
from vinculum.parsers.nikto import NiktoParser
from vinculum.parsers.nmap import NmapParser
from vinculum.parsers.nubicustos import NubicustosParser
from vinculum.parsers.nubicustos_containers import NubicustosContainersParser
from vinculum.parsers.nuclei import NucleiParser
from vinculum.parsers.reticustos import ReticustosParser
from vinculum.parsers.reticustos_endpoints import ReticustosEndpointsParser
from vinculum.parsers.semgrep import SemgrepParser
from vinculum.parsers.snyk import SnykParser
from vinculum.parsers.trivy import TrivyParser
from vinculum.parsers.zap import ZAPParser
from vinculum.suppression import SuppressionManager

console = Console()

# Register parsers — order matters!
# Ecosystem parsers with specific format-key detection go first
ParserRegistry.register(AriadneParser())
ParserRegistry.register(AriadneReportParser())
ParserRegistry.register(ReticustosEndpointsParser())
ParserRegistry.register(NubicustosContainersParser())
# Existing parsers with specific detection
ParserRegistry.register(BurpParser())
ParserRegistry.register(BypassBurritoParser())
ParserRegistry.register(CepheusParser())
ParserRegistry.register(IndagoParser())
ParserRegistry.register(MobilicustosParser())
ParserRegistry.register(NessusParser())
ParserRegistry.register(NubicustosParser())
ParserRegistry.register(NucleiParser())
ParserRegistry.register(ReticustosParser())
# New third-party parsers with specific detection
ParserRegistry.register(GrypeParser())
ParserRegistry.register(SnykParser())
ParserRegistry.register(DependencyCheckParser())
ParserRegistry.register(CheckovParser())
ParserRegistry.register(MobSFParser())
ParserRegistry.register(NiktoParser())
ParserRegistry.register(NmapParser())
# Broad-match parsers LAST
ParserRegistry.register(SemgrepParser())
ParserRegistry.register(TrivyParser())
ParserRegistry.register(ZAPParser())


@click.group()
@click.version_option(version=__version__, prog_name="vinculum")
def cli():
    """Vinculum - Bind and correlate security findings across tools."""
    pass


@cli.command()
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.option(
    "--config",
    "-c",
    "config_path",
    type=click.Path(exists=True),
    help="Path to configuration file",
)
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["json", "console", "sarif", "ariadne", "burrito"]),
    default=None,
    help="Output format (default: console)",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Output file path (required for json/sarif format)",
)
@click.option(
    "--min-severity",
    type=click.Choice(["critical", "high", "medium", "low", "info"]),
    default=None,
    help="Minimum severity to include (default: info)",
)
@click.option(
    "--ai-provider",
    type=click.Choice(["claude", "openai", "ollama", "lmstudio"]),
    default=None,
    help="AI provider for semantic correlation",
)
@click.option(
    "--ai-model",
    default=None,
    help="AI model to use (provider-specific)",
)
@click.option(
    "--ai-base-url",
    default=None,
    help="Base URL for local AI providers (ollama, lmstudio)",
)
@click.option(
    "--enrich-epss/--no-enrich-epss",
    default=None,
    help="Enrich findings with EPSS scores",
)
@click.option(
    "--include-raw/--no-include-raw",
    default=None,
    help="Include raw tool data in JSON output",
)
@click.option(
    "--log-level",
    type=click.Choice(["debug", "info", "warning", "error"]),
    default=None,
    help="Logging level",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Verbose output",
)
@click.option(
    "--run-id",
    default=None,
    help="Pipeline run identifier for tracking and correlation across executions",
)
@click.option(
    "--parser-dir",
    multiple=True,
    type=click.Path(exists=True, file_okay=False),
    help="Directory containing custom parser plugins (can be specified multiple times)",
)
@click.option(
    "--baseline",
    type=click.Path(exists=True),
    default=None,
    help="Path to previous JSON results for incremental correlation",
)
def ingest(
    files,
    config_path,
    output_format,
    output,
    min_severity,
    ai_provider,
    ai_model,
    ai_base_url,
    enrich_epss,
    include_raw,
    log_level,
    verbose,
    run_id,
    parser_dir,
    baseline,
):
    """
    Ingest security findings from multiple tool outputs.

    FILES: One or more files to ingest (Burp XML, Nessus XML, Semgrep JSON, etc.)
    """
    from vinculum.models.enums import Severity

    # Load custom parser plugins
    plugin_dirs = [Path(d) for d in parser_dir]
    default_plugin_dir = Path.home() / ".vinculum" / "parsers"
    if default_plugin_dir.is_dir():
        plugin_dirs.append(default_plugin_dir)
    if plugin_dirs:
        loaded = ParserRegistry.load_plugins(plugin_dirs)
        if loaded > 0 and verbose:
            console.print(f"[dim]Loaded {loaded} custom parser plugin(s)[/dim]")

    # Load and merge configuration
    base_config = load_config(Path(config_path) if config_path else None)
    config = merge_cli_with_config(
        base_config,
        output_format=output_format,
        output_path=output,
        min_severity=min_severity,
        ai_provider=ai_provider,
        ai_model=ai_model,
        ai_base_url=ai_base_url,
        enrich_epss=enrich_epss,
        include_raw=include_raw,
        log_level=log_level,
    )

    # Set up logging
    setup_logging(level=config.logging.level, log_file=config.logging.file)

    # Parse all files
    all_findings: list[UnifiedFinding] = []
    parsed_files = 0
    file_list = list(files)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        parse_task = progress.add_task("[green]Parsing files...", total=len(file_list))

        for file_path_str in file_list:
            file_path = Path(file_path_str)
            parser = ParserRegistry.get_parser_for_file(file_path)

            if parser is None:
                console.print(f"[yellow]Warning: No parser found for {file_path}[/yellow]")
                progress.advance(parse_task)
                continue

            try:
                progress.update(
                    parse_task,
                    description=f"[green]Parsing {file_path.name} ({parser.tool_name})...",
                )
                findings = parser.parse(file_path)
                all_findings.extend(findings)
                parsed_files += 1
                if verbose:
                    console.print(
                        f"  [green]✓[/green] {file_path.name}: {len(findings)} findings"
                    )
            except ParseError as e:
                console.print(f"[red]Error parsing {file_path}: {e}[/red]")
            finally:
                progress.advance(parse_task)

    if not all_findings:
        console.print("[red]No findings parsed from any file[/red]")
        sys.exit(1)

    console.print(
        f"[green]Parsed {len(all_findings)} findings from {parsed_files} file(s)[/green]"
    )

    # Apply suppression rules if configured
    if config.suppressions:
        suppression_manager = SuppressionManager.from_config(config.suppressions)
        suppression_result = suppression_manager.filter_findings(all_findings)
        if suppression_result.suppressed_count > 0:
            console.print(
                f"[dim]Suppressed {suppression_result.suppressed_count} finding(s) "
                f"by {len(suppression_manager.rules)} rule(s)[/dim]"
            )
        all_findings = suppression_result.kept

    # Filter by severity
    effective_min_severity = config.correlation.min_severity
    min_sev = Severity.from_string(effective_min_severity)
    if min_sev != Severity.INFO:
        original_count = len(all_findings)
        all_findings = [
            f for f in all_findings if Severity(f.severity).numeric >= min_sev.numeric
        ]
        console.print(
            f"[dim]Filtered to {len(all_findings)} findings (min severity: {effective_min_severity})[/dim]"
        )

    # Set up AI correlator if requested
    ai_correlator = None
    effective_ai_provider = config.ai.provider
    if effective_ai_provider:
        try:
            ai_correlator = get_ai_correlator(
                effective_ai_provider,
                model=config.ai.model,
                base_url=config.ai.base_url,
            )
            console.print(f"[dim]AI correlation enabled: {effective_ai_provider}[/dim]")
        except Exception as e:
            console.print(f"[yellow]Warning: Could not initialize AI correlator: {e}[/yellow]")

    # Correlate findings with progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        metadata = {}
        if run_id:
            metadata["run_id"] = run_id

        if baseline:
            import json as _json

            progress.add_task("[green]Loading baseline and correlating incrementally...", total=None)
            with open(baseline) as bf:
                baseline_data = _json.load(bf)
            baseline_result = CorrelationResult.from_dict(baseline_data)
            engine = CorrelationEngine(ai_correlator=ai_correlator)
            groups = engine.incremental_correlate(all_findings, baseline_result)
            baseline_count = sum(len(g.findings) for g in baseline_result.groups)
            result = CorrelationResult(groups, baseline_count + len(all_findings), metadata=metadata)
        else:
            progress.add_task("[green]Correlating findings...", total=None)
            result = correlate_findings(all_findings, ai_correlator=ai_correlator, metadata=metadata)

    console.print(
        f"[green]Correlated to {result.unique_count} unique issues "
        f"({result.dedup_rate:.1f}% deduplication)[/green]"
    )

    # Cross-tool enrichment (always active, no-op when no relevant combos)
    enricher_ct = CrossToolEnricher()
    enricher_ct.enrich(result)

    # Enrich with EPSS if requested
    if config.correlation.enrich_epss:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
            transient=True,
        ) as progress:
            enrich_task = progress.add_task(
                "[green]Enriching with EPSS scores...", total=len(result.groups)
            )
            enricher = EPSSEnricher()
            for group in result.groups:
                enricher.enrich(group.findings)
                progress.advance(enrich_task)

        enriched = sum(1 for g in result.groups for f in g.findings if f.epss_score is not None)
        console.print(f"[dim]Enriched {enriched} findings with EPSS scores[/dim]")

    # Output results
    effective_format = config.output.format
    effective_output = output or config.output.path
    effective_include_raw = config.output.include_raw if include_raw is None else include_raw

    if effective_format == "json":
        if not effective_output:
            # Output to stdout
            formatter = JSONOutputFormatter(pretty=True, include_raw=effective_include_raw)
            print(formatter.format(result))
        else:
            output_path = Path(effective_output)
            formatter = JSONOutputFormatter(pretty=True, include_raw=effective_include_raw)
            formatter.write(result, output_path)
            console.print(f"[green]Results written to {output_path}[/green]")
    elif effective_format == "sarif":
        if not effective_output:
            # Output to stdout
            formatter = SARIFOutputFormatter(pretty=True)
            print(formatter.format(result))
        else:
            output_path = Path(effective_output)
            formatter = SARIFOutputFormatter(pretty=True)
            formatter.write(result, output_path)
            console.print(f"[green]SARIF results written to {output_path}[/green]")
    elif effective_format == "ariadne":
        if not effective_output:
            formatter = AriadneOutputFormatter(pretty=True, include_raw=effective_include_raw)
            print(formatter.format(result))
        else:
            output_path = Path(effective_output)
            formatter = AriadneOutputFormatter(pretty=True, include_raw=effective_include_raw)
            formatter.write(result, output_path)
            console.print(f"[green]Ariadne export written to {output_path}[/green]")
    elif effective_format == "burrito":
        if not effective_output:
            formatter = BurritoOutputFormatter(pretty=True)
            print(formatter.format(result))
        else:
            output_path = Path(effective_output)
            formatter = BurritoOutputFormatter(pretty=True)
            formatter.write(result, output_path)
            console.print(f"[green]BypassBurrito export written to {output_path}[/green]")
    else:
        formatter = ConsoleOutputFormatter(console=console, verbose=verbose)
        formatter.print(result)


@cli.command()
@click.argument("results_file", type=click.Path(exists=True))
def stats(results_file):
    """
    Show statistics from a results JSON file.

    RESULTS_FILE: JSON file from a previous ingest run
    """
    import json

    with open(results_file) as f:
        data = json.load(f)

    summary = data.get("summary", {})

    table_data = [
        ("Total Findings", summary.get("total_findings", 0)),
        ("Unique Issues", summary.get("unique_issues", 0)),
        ("Duplicates Removed", summary.get("duplicates_removed", 0)),
        ("Deduplication Rate", f"{summary.get('deduplication_rate', 0)}%"),
        ("Multi-Tool Detections", summary.get("multi_tool_detections", 0)),
    ]

    console.print("\n[bold]Summary Statistics[/bold]")
    for label, value in table_data:
        console.print(f"  {label}: [cyan]{value}[/cyan]")

    console.print("\n[bold]By Severity[/bold]")
    for sev, count in summary.get("by_severity", {}).items():
        console.print(f"  {sev.upper()}: {count}")

    console.print("\n[bold]By Tool[/bold]")
    for tool, count in summary.get("by_tool", {}).items():
        console.print(f"  {tool}: {count}")


@cli.command()
@click.argument("file1", type=click.Path(exists=True))
@click.argument("file2", type=click.Path(exists=True))
def diff(file1, file2):
    """
    Compare two results files and show differences.

    FILE1: First results JSON file (baseline)
    FILE2: Second results JSON file (new)
    """
    import json

    with open(file1) as f:
        data1 = json.load(f)
    with open(file2) as f:
        data2 = json.load(f)

    # Extract correlation IDs
    groups1 = {g["correlation_id"]: g for g in data1.get("groups", [])}
    groups2 = {g["correlation_id"]: g for g in data2.get("groups", [])}

    ids1 = set(groups1.keys())
    ids2 = set(groups2.keys())

    new_ids = ids2 - ids1
    fixed_ids = ids1 - ids2
    common_ids = ids1 & ids2

    console.print(f"\n[bold]Comparison: {file1} → {file2}[/bold]\n")
    console.print(f"  Baseline issues: {len(ids1)}")
    console.print(f"  Current issues: {len(ids2)}")
    console.print(f"  [green]New issues: {len(new_ids)}[/green]")
    console.print(f"  [red]Fixed/removed: {len(fixed_ids)}[/red]")
    console.print(f"  Unchanged: {len(common_ids)}")

    if new_ids:
        console.print("\n[bold green]New Issues:[/bold green]")
        for cid in list(new_ids)[:10]:
            group = groups2[cid]
            primary = group.get("primary", {})
            console.print(
                f"  • [{primary.get('severity', 'info').upper()}] {primary.get('title', 'Unknown')}"
            )
        if len(new_ids) > 10:
            console.print(f"  ... and {len(new_ids) - 10} more")

    if fixed_ids:
        console.print("\n[bold red]Fixed/Removed Issues:[/bold red]")
        for cid in list(fixed_ids)[:10]:
            group = groups1[cid]
            primary = group.get("primary", {})
            console.print(
                f"  • [{primary.get('severity', 'info').upper()}] {primary.get('title', 'Unknown')}"
            )
        if len(fixed_ids) > 10:
            console.print(f"  ... and {len(fixed_ids) - 10} more")


@cli.command()
def parsers():
    """List available parsers."""
    console.print("\n[bold]Available Parsers[/bold]\n")
    for parser in ParserRegistry.get_all_parsers():
        console.print(f"  • [cyan]{parser.tool_name}[/cyan]")
        console.print(f"    Extensions: {', '.join(parser.supported_extensions)}")


if __name__ == "__main__":
    cli()
