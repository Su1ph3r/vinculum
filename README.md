# Vinculum

Deduplicates and correlates security findings across tools.

## Supported tools

Burp Suite, Nessus, Semgrep, Nuclei, Trivy, OWASP ZAP, Snyk, Grype,
Checkov, MobSF, OWASP Dependency-Check, Nikto, Nmap, Reticustos,
Nubicustos, Indago, Mobilicustos, Cepheus, BypassBurrito, Ariadne.

## Install

```bash
pip install vinculum
```

## Usage

```bash
# ingest files
vinculum ingest burp_scan.xml nessus_scan.nessus semgrep_results.json

# ingest a directory
vinculum ingest scan_results/*

# correlate incrementally against a baseline
vinculum ingest new_scan.json --baseline results.json -o updated.json

# export as JSON
vinculum ingest scan_results/* -f json -o results.json

# export as SARIF
vinculum ingest scan_results/* -f sarif -o results.sarif

# export for Ariadne
vinculum ingest scan_results/* -f ariadne -o findings.json

# filter by severity, enrich with EPSS
vinculum ingest findings.xml --min-severity high --enrich-epss

# load custom parsers
vinculum ingest custom_tool.xyz --parser-dir ./my-parsers/ -f json -o results.json

# compare two result sets
vinculum diff baseline.json current.json

# show stats
vinculum stats results.json
```

## Export formats

JSON, SARIF 2.1.0, Ariadne, BypassBurrito, console.

## Suppression rules

```yaml
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

## Configuration

```yaml
output:
  format: sarif
  pretty: true

correlation:
  min_severity: medium
  enrich_epss: true

logging:
  level: info
```

Place as `vinculum.yaml` in your project root, or pass `--config path/to/config.yaml`.

## License

MIT
