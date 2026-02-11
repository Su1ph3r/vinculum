# Vinculum

*Latin: "bond, link, chain"*

**Vinculum** is a security finding correlation engine that unifies, deduplicates, and correlates vulnerability findings from multiple security tools.

## Features

- **Multi-Tool Ingestion**: Parse findings from 13 security tools including Burp Suite, Nessus, Semgrep, Nuclei, Trivy, OWASP ZAP, Reticustos, Nubicustos, Indago, Mobilicustos, Cepheus, BypassBurrito, and Ariadne (closed-loop)
- **Intelligent Correlation**: Deduplicate findings across tools using fingerprint-based and semantic matching
- **Cross-Tool Enrichment**: Automatic linking of findings across tool boundaries with confidence boosting and provenance chains
- **Incremental Correlation**: Re-correlate against a baseline to process only new findings (`--baseline`)
- **Custom Parser Plugins**: Load parsers from external directories (`--parser-dir`)
- **SARIF Output**: Export results in SARIF 2.1.0 format for CI/CD integration
- **Ariadne Export**: Export correlated findings with relationship confidence weights for attack path synthesis
- **BypassBurrito Export**: Extract WAF-blocked findings as input for WAF bypass testing (`--format burrito`)
- **EPSS Enrichment**: Enrich findings with Exploit Prediction Scoring System data
- **AI-Powered Correlation**: Optional semantic correlation using OpenAI, Anthropic, Ollama, or LM Studio
- **Suppression Rules**: Filter out false positives and accepted risks via configuration
- **Configuration File Support**: YAML-based configuration with CLI override capability
- **Pipeline Integration**: Connects [Reticustos](https://github.com/Su1ph3r/reticustos) scan orchestration to [Ariadne](https://github.com/Su1ph3r/ariadne) attack path synthesis

## Installation

```bash
pip install vinculum
```

Or install from source:

```bash
git clone https://github.com/yourusername/vinculum.git
cd vinculum
pip install -e .
```

## Quick Start

### Basic Usage

```bash
# Ingest findings from multiple tools
vinculum ingest burp_scan.xml nessus_scan.nessus semgrep_results.json

# Output as JSON
vinculum ingest *.xml *.json --format json --output results.json

# Output as SARIF for CI/CD
vinculum ingest scan_results/* --format sarif --output results.sarif

# Export for Ariadne attack path analysis
vinculum ingest scan_results/* --format ariadne --output findings.json

# Ingest Reticustos scan exports
vinculum ingest reticustos_export.json --format ariadne --output findings.json

# Export WAF-blocked findings for BypassBurrito
vinculum ingest indago_results.json --format burrito --output waf-targets.json

# Tag a pipeline run for tracking
vinculum ingest scan_results/* --run-id pipeline-2026-02-11 --format json --output results.json

# Incremental mode — only correlate new findings against a baseline
vinculum ingest new_scan.json --baseline results.json --format json --output updated.json

# Load custom parsers from a directory
vinculum ingest custom_tool.xyz --parser-dir ./my-parsers/ --format json --output results.json

# Filter by minimum severity
vinculum ingest findings.xml --min-severity high

# Enable EPSS enrichment
vinculum ingest findings.xml --enrich-epss
```

### Using a Configuration File

Create `vinculum.yaml` in your project root:

```yaml
ai:
  provider: ollama
  model: llama2
  base_url: http://localhost:11434

output:
  format: sarif
  pretty: true

correlation:
  min_severity: medium
  enrich_epss: true

logging:
  level: info

suppressions:
  - id: false-positive-001
    reason: Known false positive in test environment
    title_pattern: "*test*"
  - id: accepted-risk-log4j
    reason: Mitigated by WAF rules
    cve_ids:
      - CVE-2021-44228
    expires: "2025-12-31T00:00:00"
```

Then run:

```bash
vinculum ingest scan_results/* --config vinculum.yaml
```

## Supported Tools

| Tool | Format | Extension | Finding Type |
|------|--------|-----------|--------------|
| Ariadne | JSON | `.json` | Closed-loop re-ingestion |
| Burp Suite | XML | `.xml` | DAST |
| BypassBurrito | JSON | `.json` | WAF Bypass |
| Cepheus | JSON | `.json` | Container Escape |
| Indago | JSON | `.json` | API/DAST |
| Mobilicustos | JSON | `.json` | Mobile |
| Nessus | XML | `.nessus` | Network |
| Nubicustos | JSON | `.json` | Cloud (AWS/Azure/GCP/K8s) |
| Nuclei | JSONL | `.json`, `.jsonl` | DAST |
| OWASP ZAP | XML | `.xml` | DAST |
| Reticustos | JSON | `.json` | Network/DAST/SSL |
| Semgrep | JSON | `.json` | SAST |
| Trivy | JSON | `.json` | Container/Dependency |

## CLI Reference

### `vinculum ingest`

Ingest and correlate security findings from multiple tool outputs.

```
Usage: vinculum ingest [OPTIONS] FILES...

Options:
  -c, --config PATH          Path to configuration file
  -f, --format [json|console|sarif|ariadne|burrito]
                             Output format (default: console)
  -o, --output PATH          Output file path
  --min-severity [critical|high|medium|low|info]
                             Minimum severity to include
  --ai-provider [claude|openai|ollama|lmstudio]
                             AI provider for semantic correlation
  --ai-model TEXT            AI model to use
  --ai-base-url TEXT         Base URL for local AI providers
  --enrich-epss / --no-enrich-epss
                             Enrich findings with EPSS scores
  --include-raw / --no-include-raw
                             Include raw tool data in output
  --log-level [debug|info|warning|error]
                             Logging level
  -v, --verbose              Verbose output
  --run-id TEXT              Pipeline run identifier
  --parser-dir PATH          Custom parser plugin directory (repeatable)
  --baseline PATH            Previous results file for incremental correlation
```

### `vinculum stats`

Show statistics from a results JSON file.

```bash
vinculum stats results.json
```

### `vinculum diff`

Compare two results files and show differences.

```bash
vinculum diff baseline.json current.json
```

### `vinculum parsers`

List available parsers.

```bash
vinculum parsers
```

## Python API

### Basic Usage

```python
from vinculum import (
    UnifiedFinding,
    CorrelationEngine,
    correlate_findings,
    Severity,
    Confidence,
)
from vinculum.parsers import BurpParser, NessusParser, SemgrepParser

# Parse findings from files
burp_parser = BurpParser()
nessus_parser = NessusParser()

findings = []
findings.extend(burp_parser.parse("burp_scan.xml"))
findings.extend(nessus_parser.parse("nessus_scan.nessus"))

# Correlate findings
result = correlate_findings(findings)

print(f"Total findings: {result.total_count}")
print(f"Unique issues: {result.unique_count}")
print(f"Deduplication rate: {result.dedup_rate:.1f}%")

# Access correlated groups
for group in result.groups:
    print(f"- {group.primary.title} ({group.primary.severity})")
    print(f"  Detected by: {[f.source_tool for f in group.findings]}")
```

### SARIF Output

```python
from vinculum.output import SARIFOutputFormatter

formatter = SARIFOutputFormatter(pretty=True)
sarif_json = formatter.format(result)

# Or write directly to file
formatter.write(result, "results.sarif")
```

### Ariadne Export

```python
from vinculum.output import AriadneOutputFormatter

formatter = AriadneOutputFormatter(pretty=True)
ariadne_json = formatter.format(result)

# Or write directly to file
formatter.write(result, "findings_for_ariadne.json")
```

### Suppression Rules

```python
from vinculum.suppression import SuppressionManager, SuppressionRule

# Create suppression rules
rules = [
    SuppressionRule(
        id="fp-001",
        reason="False positive in test code",
        title_pattern="*test*",
    ),
    SuppressionRule(
        id="accepted-risk",
        reason="Accepted risk per security review",
        cve_ids=["CVE-2021-44228"],
    ),
]

manager = SuppressionManager(rules)
result = manager.filter_findings(findings)

print(f"Kept: {result.kept_count}")
print(f"Suppressed: {result.suppressed_count}")
```

### Configuration

```python
from vinculum.config import load_config, merge_cli_with_config

# Load from file
config = load_config("vinculum.yaml")

# Or merge with CLI options
config = merge_cli_with_config(
    config,
    output_format="sarif",
    min_severity="high",
)
```

## Output Formats

### Console (Default)

Human-readable output with severity-based coloring and grouping.

### JSON

Structured JSON with full finding details, correlation groups, and summary statistics.

### SARIF 2.1.0

Standard format for static analysis tools, compatible with:
- GitHub Code Scanning
- Azure DevOps
- GitLab SAST
- Many CI/CD platforms

### Ariadne

Structured JSON export (`vinculum-ariadne-export` format) designed for ingestion by [Ariadne](https://github.com/Su1ph3r/ariadne). Contains hosts, services, vulnerabilities, misconfigurations, and relationships with Vinculum correlation metadata (fingerprints, source tools, EPSS scores) preserved for graph enrichment. Relationships include confidence weights and evidence strength scores.

### BypassBurrito

Extracts WAF-blocked Indago findings and formats them as targets for [BypassBurrito](https://github.com/Su1ph3r/bypassburrito) WAF bypass payload generation. Detects WAF blocking by status codes (403/406/429), WAF keywords, and tags.

## Architecture

```
vinculum/
├── cli.py              # CLI interface
├── config.py           # Configuration management
├── logging.py          # Logging infrastructure
├── suppression.py      # Finding suppression rules
├── models/
│   ├── finding.py      # UnifiedFinding, FindingLocation, CorrelationGroup
│   └── enums.py        # Severity, Confidence, FindingType
├── parsers/
│   ├── base.py         # BaseParser, ParserRegistry, plugin loading
│   ├── ariadne.py      # Ariadne closed-loop parser
│   ├── burp.py         # Burp Suite XML parser
│   ├── bypassburrito.py # BypassBurrito WAF bypass parser
│   ├── cepheus.py      # Cepheus container escape parser
│   ├── indago.py       # Indago API fuzzer parser
│   ├── mobilicustos.py # Mobilicustos mobile parser
│   ├── nessus.py       # Nessus XML parser
│   ├── nubicustos.py   # Nubicustos cloud parser
│   ├── nuclei.py       # Nuclei JSONL parser
│   ├── reticustos.py   # Reticustos JSON parser
│   ├── semgrep.py      # Semgrep JSON parser
│   ├── trivy.py        # Trivy JSON parser
│   └── zap.py          # OWASP ZAP XML parser
├── correlation/
│   ├── engine.py       # Correlation engine (full + incremental)
│   ├── fingerprint.py  # Fingerprint generation
│   └── ai_correlator.py # AI-powered correlation
├── output/
│   ├── ariadne_output.py  # Ariadne export with confidence weights
│   ├── burrito_output.py  # BypassBurrito export formatter
│   ├── console_output.py  # Console formatter
│   ├── json_output.py     # JSON formatter
│   └── sarif_output.py    # SARIF formatter
└── enrichment/
    ├── cross_tool.py   # Cross-tool enrichment + provenance chains
    └── epss.py         # EPSS score enrichment
```

## Cross-Tool Integration

Vinculum is the central correlation engine in a cross-tool security pipeline connecting 7 specialized tools:

```
Nubicustos (cloud) ──containers──> Cepheus (container escape)
Reticustos (network) ──endpoints──> Indago (API fuzzing)
Indago (API fuzzing) ──WAF-blocked──> BypassBurrito (WAF bypass)
Ariadne (attack paths) ──endpoints──> Indago (API fuzzing)
All tools ──findings──> Vinculum (correlation) ──export──> Ariadne (attack paths)
```

### Importing Findings

Vinculum ingests findings from all 13 supported tools. Each parser auto-detects its format:

```bash
# Ingest from any combination of tools
vinculum ingest reticustos_export.json nubicustos_findings.json \
  indago_results.json cepheus_report.json \
  --format ariadne --output correlated.json

# Ingest Reticustos scan exports
curl -o scan_export.json "http://localhost:8000/api/exports/findings/json?scan_id=SCAN_ID"
vinculum ingest scan_export.json --enrich-epss --format ariadne --output correlated.json
```

### Exporting to Ariadne

The Ariadne v1.1 export includes extended entity types for richer knowledge graphs:

```bash
vinculum ingest scan_results/* --format ariadne --output findings.json
ariadne analyze findings.json --output report --format html --playbook
```

The export preserves cloud resources, containers, mobile apps, API endpoints, and Vinculum correlation metadata (fingerprints, source tools, EPSS scores, correlation IDs) for enriched attack path scoring.

See also: [Nubicustos](https://github.com/Su1ph3r/Nubicustos) | [Reticustos](https://github.com/Su1ph3r/Reticustos) | [Indago](https://github.com/Su1ph3r/indago) | [BypassBurrito](https://github.com/Su1ph3r/bypassburrito) | [Cepheus](https://github.com/Su1ph3r/Cepheus) | [Ariadne](https://github.com/Su1ph3r/ariadne)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) for details.
