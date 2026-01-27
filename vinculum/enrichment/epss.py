"""EPSS (Exploit Prediction Scoring System) enrichment."""

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from vinculum.models.finding import UnifiedFinding


class EPSSEnricher:
    """
    Enricher that fetches EPSS scores for findings with CVEs.

    EPSS (Exploit Prediction Scoring System) provides probability scores
    indicating the likelihood that a vulnerability will be exploited.
    """

    EPSS_API_URL = "https://api.first.org/data/v1/epss"
    CACHE_TTL = timedelta(hours=24)

    def __init__(self, timeout: float = 30.0):
        """
        Initialize the EPSS enricher.

        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
        self._cache: dict[str, dict[str, Any]] = {}
        self._cache_time: datetime | None = None

    def enrich(self, findings: list[UnifiedFinding]) -> list[UnifiedFinding]:
        """
        Enrich findings with EPSS scores.

        Args:
            findings: List of findings to enrich

        Returns:
            List of enriched findings
        """
        # Collect all unique CVEs
        cves = set()
        for finding in findings:
            cves.update(finding.cve_ids)

        if not cves:
            return findings

        # Fetch EPSS data
        epss_data = self._fetch_epss_batch(list(cves))

        # Apply scores to findings
        for finding in findings:
            for cve in finding.cve_ids:
                if cve in epss_data:
                    data = epss_data[cve]
                    # Use highest score if multiple CVEs
                    if finding.epss_score is None or data["epss"] > finding.epss_score:
                        finding.epss_score = data["epss"]
                        finding.epss_percentile = data["percentile"]

        return findings

    async def enrich_async(self, findings: list[UnifiedFinding]) -> list[UnifiedFinding]:
        """Async version of enrich."""
        cves = set()
        for finding in findings:
            cves.update(finding.cve_ids)

        if not cves:
            return findings

        epss_data = await self._fetch_epss_batch_async(list(cves))

        for finding in findings:
            for cve in finding.cve_ids:
                if cve in epss_data:
                    data = epss_data[cve]
                    if finding.epss_score is None or data["epss"] > finding.epss_score:
                        finding.epss_score = data["epss"]
                        finding.epss_percentile = data["percentile"]

        return findings

    def _fetch_epss_batch(self, cves: list[str]) -> dict[str, dict[str, Any]]:
        """Fetch EPSS scores for a batch of CVEs."""
        # Check cache
        if self._is_cache_valid():
            result = {}
            uncached = []
            for cve in cves:
                if cve in self._cache:
                    result[cve] = self._cache[cve]
                else:
                    uncached.append(cve)
            if not uncached:
                return result
            cves = uncached
        else:
            result = {}

        # Fetch in batches of 100 (API limit)
        batch_size = 100
        for i in range(0, len(cves), batch_size):
            batch = cves[i : i + batch_size]
            try:
                batch_result = self._fetch_epss_api(batch)
                result.update(batch_result)
                self._cache.update(batch_result)
            except Exception:
                # Continue without EPSS on error
                pass

        self._cache_time = datetime.now(timezone.utc)
        return result

    async def _fetch_epss_batch_async(self, cves: list[str]) -> dict[str, dict[str, Any]]:
        """Async fetch EPSS scores for a batch of CVEs."""
        if self._is_cache_valid():
            result = {}
            uncached = []
            for cve in cves:
                if cve in self._cache:
                    result[cve] = self._cache[cve]
                else:
                    uncached.append(cve)
            if not uncached:
                return result
            cves = uncached
        else:
            result = {}

        batch_size = 100
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for i in range(0, len(cves), batch_size):
                batch = cves[i : i + batch_size]
                try:
                    batch_result = await self._fetch_epss_api_async(client, batch)
                    result.update(batch_result)
                    self._cache.update(batch_result)
                except Exception:
                    pass

        self._cache_time = datetime.now(timezone.utc)
        return result

    def _fetch_epss_api(self, cves: list[str]) -> dict[str, dict[str, Any]]:
        """Fetch EPSS scores from the API."""
        cve_param = ",".join(cves)
        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(
                self.EPSS_API_URL,
                params={"cve": cve_param},
            )
            response.raise_for_status()
            return self._parse_epss_response(response.json())

    async def _fetch_epss_api_async(
        self, client: httpx.AsyncClient, cves: list[str]
    ) -> dict[str, dict[str, Any]]:
        """Async fetch EPSS scores from the API."""
        cve_param = ",".join(cves)
        response = await client.get(
            self.EPSS_API_URL,
            params={"cve": cve_param},
        )
        response.raise_for_status()
        return self._parse_epss_response(response.json())

    def _parse_epss_response(self, data: dict) -> dict[str, dict[str, Any]]:
        """Parse EPSS API response."""
        result = {}
        for item in data.get("data", []):
            cve = item.get("cve", "").upper()
            if cve:
                result[cve] = {
                    "epss": float(item.get("epss", 0)),
                    "percentile": float(item.get("percentile", 0)),
                    "date": item.get("date"),
                }
        return result

    def _is_cache_valid(self) -> bool:
        """Check if cache is still valid."""
        if self._cache_time is None:
            return False
        return datetime.now(timezone.utc) - self._cache_time < self.CACHE_TTL

    def clear_cache(self) -> None:
        """Clear the EPSS cache."""
        self._cache = {}
        self._cache_time = None


def enrich_with_epss(findings: list[UnifiedFinding]) -> list[UnifiedFinding]:
    """Convenience function to enrich findings with EPSS scores."""
    enricher = EPSSEnricher()
    return enricher.enrich(findings)
