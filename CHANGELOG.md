# Changelog

All notable changes to Vinculum will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `--force-parser` CLI flag to bypass auto-detection and force a specific parser by tool_name
- `ParserRegistry.get_parser_by_name()` classmethod for programmatic parser lookup
- `AriadneParser` now exported from `vinculum.parsers` module

### Changed
- Parser error handling hardened across all 23 parsers (7 legacy parsers now match the pattern from v0.4.0):
  - trivy, semgrep, burp, nuclei, zap, nessus, reticustos now have per-item try/except with skip counters
- Parser error handling hardened across all 10 new parsers:
  - Failure threshold: raises `ParseError` when 100% of items fail to parse (detects schema changes)
  - Narrowed exception types from broad `Exception` to `(KeyError, TypeError, ValueError, IndexError, AttributeError)`
  - Added `except ParseError: raise` guards to prevent error double-wrapping
  - Tool-specific warning messages for skipped items include parser name
  - Error-level logging when items are skipped with total/skipped counts
  - Warnings logged for missing required fields (empty IDs, missing names)
  - Unknown severity strings now default to MEDIUM (was INFO) with logged warning
  - MobSF sub-parser methods now include file path context in error messages

## [0.4.0] - 2026-02-11

### Added

#### Ecosystem Parsers
- **Reticustos Endpoints** parser (`reticustos:endpoints`) for endpoint inventory exports (`reticustos-endpoints` format) — produces INFO/DAST findings for each discovered API endpoint with URL, method, host/port location and discovery metadata tags
- **Nubicustos Containers** parser (`nubicustos:containers`) for container inventory exports (`nubicustos-containers` format) — produces INFO/CONTAINER findings with image, namespace, runtime, privileged flag, and port tags
- **Ariadne Report** parser (`ariadne:report`) for attack path reports (`ariadne-report` format) — severity derived from highest-severity node in each path, finding type from node types, CVEs/CWEs aggregated across all nodes, MITRE technique tags, playbook as evidence

#### Third-Party JSON Parsers
- **Snyk** parser for Snyk SCA/SAST vulnerability scanner output — maps `vulnerabilities[]` to DEPENDENCY or SAST findings with CVE/CWE identifiers, CVSS scores/vectors, fix version remediation, and package path location
- **Grype** parser for Anchore Grype container/dependency scanner output — maps `matches[]` to CONTAINER (OS packages) or DEPENDENCY findings with CVE extraction, CVSS metrics, and fix/not-fixed remediation
- **Checkov** parser for Bridgecrew Checkov IaC scanner output — supports both list format (multiple check types) and dict format; maps failed checks to CLOUD (terraform/cloudformation/arm/bicep), CONTAINER (dockerfile/kubernetes/helm), or OTHER findings with file location, line ranges, and CWE from `bc_check_id`
- **MobSF** parser for Mobile Security Framework scan output — parses code_analysis, manifest_analysis, binary_analysis, and certificate_analysis sections; auto-detects Android/iOS platform; per-file findings for code analysis

#### Third-Party XML Parsers
- **OWASP Dependency-Check** parser for Dependency-Check reports — supports both XML and JSON dual format; CVSS score-based severity mapping (>=9 CRITICAL, >=7 HIGH, >=4 MEDIUM, else LOW); namespace-aware XML parsing
- **Nikto** parser for Nikto web scanner XML output — keyword-based severity heuristic with OSVDB presence bump (LOW→MEDIUM, MEDIUM→HIGH, HIGH→CRITICAL); FIRM confidence for all findings
- **Nmap** parser for Nmap XML scan output — two finding types: open ports (INFO/NETWORK/CERTAIN) and NSE script vulnerabilities (HIGH if CVE extracted via regex, MEDIUM otherwise); filters out "NOT VULNERABLE" scripts

### Changed
- CLI now registers 23 parsers (up from 13) with explicit ordering: ecosystem-specific parsers first, then existing parsers, then new third-party parsers, with broad-match parsers (Semgrep, Trivy, ZAP) registered last to prevent false matches
- Version bumped to 0.4.0

## [0.3.0] - 2026-02-11

### Added

#### Pipeline Run Metadata
- `--run-id` flag for tracking pipeline executions across runs
- Run ID included in JSON, Ariadne, SARIF, and console output metadata

#### Custom Parser Plugin System
- `--parser-dir` flag for loading custom parser plugins from external directories
- Auto-scan of `~/.vinculum/parsers/` for user-installed parsers
- `ParserRegistry.load_plugins()` for dynamic parser discovery via `importlib`

#### Ariadne Parser (Closed-Loop Feedback)
- New `AriadneParser` for re-ingesting Vinculum's own Ariadne export (`vinculum-ariadne-export` v1.1)
- Preserves `vinculum_metadata` (correlation_id, fingerprint, source_tools) for round-trip correlation
- Enables iterative enrichment: Ariadne output → Vinculum re-ingestion → enhanced correlation

#### Cross-Tool Enrichment
- `CrossToolEnricher` links findings across tool boundaries within correlation groups:
  - Indago ↔ BypassBurrito: marks `exploitation_confirmed` when WAF bypass succeeds
  - Indago ↔ Reticustos: enriches API findings with service/version info
  - Cepheus ↔ Nubicustos: attaches cloud resource context to container escape findings
- Confidence boosting: automatically sets `confidence=CERTAIN` when 2+ tools confirm the same issue
- Provenance chains: ordered tool pipeline per group (reticustos→indago→bypassburrito→nubicustos→cepheus)

#### Relationship Confidence Weights in Ariadne Export
- Each relationship now includes `confidence` (certain/firm/tentative), `evidence_strength` (0.0-1.0), and `confirmed_by` fields
- Evidence strength factors: multi-tool (+0.25/tool, cap 0.5), CVE presence (+0.2), exploitation confirmed (+0.3)

#### BypassBurrito Export Format
- `--format burrito` exports WAF-blocked Indago findings as BypassBurrito input targets
- Detects WAF-blocked requests by status codes (403/406/429), WAF keywords, and tags
- Maps CWE IDs to vulnerability types (SQLi, XSS, Command Injection, etc.)

#### Incremental Correlation
- `--baseline` flag for incremental ingestion against a previous results file
- `CorrelationResult.to_dict()` / `from_dict()` for serializing and restoring baselines
- `CorrelationEngine.incremental_correlate()` indexes baseline groups and only processes new findings

### Changed
- CLI now registers 13 parsers (up from 12) including Ariadne
- `UnifiedFinding` model adds `exploitation_confirmed` and `confirmed_by` fields
- `CorrelationGroup` model adds `provenance_chain` field
- `CorrelationResult` accepts optional `metadata` dict
- Output config format choices now include `ariadne` and `burrito`
- Version bumped to 0.3.0

## [0.2.0] - 2026-02-09

### Added

#### New Parsers
- **Nubicustos** parser for cloud security findings (Prowler, ScoutSuite, CloudSploit, etc.)
- **Indago** parser for API security fuzzing results (SQLi, XSS, IDOR, auth bypass, etc.)
- **Mobilicustos** parser for mobile application security findings
- **Cepheus** parser for container escape scenario analysis (escape chains, techniques, CVEs)
- **BypassBurrito** parser for WAF bypass testing results (supports single object and array formats)

#### Ariadne Output v1.1
- `cloud_resources` entity type for cloud infrastructure findings (Nubicustos)
- `containers` entity type for container escape findings (Cepheus)
- `mobile_apps` entity type for mobile security findings (Mobilicustos)
- `api_endpoints` entity type for API security findings (Indago)
- New relationship types: `has_cloud_vulnerability`, `has_container_escape`, `has_mobile_vulnerability`, `has_api_vulnerability`

#### Cross-Tool Integration
- Vinculum now participates in a cross-tool security pipeline connecting 7 tools
- Nubicustos, Indago, Cepheus, BypassBurrito, and Mobilicustos findings flow through Vinculum for correlation and enrichment before export to Ariadne

### Changed
- CLI now registers 12 parsers (up from 7)
- Ariadne output format version bumped to 1.1

## [0.1.0] - 2026-01-25

### Added
- Initial release
- Multi-tool ingestion: Burp Suite, Nessus, Semgrep, Nuclei, Trivy, OWASP ZAP, Reticustos
- Fingerprint-based and semantic correlation engine
- SARIF 2.1.0 output for CI/CD integration
- Ariadne export format for attack path synthesis
- EPSS score enrichment
- AI-powered semantic correlation (OpenAI, Anthropic, Ollama, LM Studio)
- YAML-based suppression rules
- Configuration file support with CLI overrides

[Unreleased]: https://github.com/Su1ph3r/vinculum/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Su1ph3r/vinculum/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Su1ph3r/vinculum/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Su1ph3r/vinculum/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Su1ph3r/vinculum/releases/tag/v0.1.0
