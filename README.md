# Vinculum

*Latin: "bond, link, chain"*

**Vinculum** is a security finding correlation engine that unifies, deduplicates, and correlates vulnerability findings from multiple security tools.

## Features

- **Multi-Tool Ingestion**: Parse findings from Burp Suite, Nessus, Semgrep, Nuclei, Trivy, and OWASP ZAP
- **Intelligent Correlation**: Deduplicate findings across tools using fingerprint-based and semantic matching
- **SARIF Output**: Export results in SARIF 2.1.0 format for CI/CD integration
- **EPSS Enrichment**: Enrich findings with Exploit Prediction Scoring System data
- **AI-Powered Correlation**: Optional semantic correlation using OpenAI, Anthropic, Ollama, or LM Studio
- **Suppression Rules**: Filter out false positives and accepted risks via configuration
- **Configuration File Support**: YAML-based configuration with CLI override capability

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
| Burp Suite | XML | `.xml` | DAST |
| Nessus | XML | `.nessus` | Network |
| Semgrep | JSON | `.json` | SAST |
| Nuclei | JSONL | `.json`, `.jsonl` | DAST |
| Trivy | JSON | `.json` | Container/Dependency |
| OWASP ZAP | XML | `.xml` | DAST |

## CLI Reference

### `vinculum ingest`

Ingest and correlate security findings from multiple tool outputs.

```
Usage: vinculum ingest [OPTIONS] FILES...

Options:
  -c, --config PATH          Path to configuration file
  -f, --format [json|console|sarif]
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
│   ├── base.py         # BaseParser, ParserRegistry
│   ├── burp.py         # Burp Suite XML parser
│   ├── nessus.py       # Nessus XML parser
│   ├── semgrep.py      # Semgrep JSON parser
│   ├── nuclei.py       # Nuclei JSONL parser
│   ├── trivy.py        # Trivy JSON parser
│   └── zap.py          # OWASP ZAP XML parser
├── correlation/
│   ├── engine.py       # Correlation engine
│   ├── fingerprint.py  # Fingerprint generation
│   └── ai_correlator.py # AI-powered correlation
├── output/
│   ├── console_output.py # Console formatter
│   ├── json_output.py    # JSON formatter
│   └── sarif_output.py   # SARIF formatter
└── enrichment/
    └── epss.py         # EPSS score enrichment
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) for details.
