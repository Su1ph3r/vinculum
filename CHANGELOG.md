# Changelog

All notable changes to Vinculum will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/Su1ph3r/vinculum/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Su1ph3r/vinculum/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Su1ph3r/vinculum/releases/tag/v0.1.0
