"""Fingerprint generation for finding deduplication."""

import hashlib
import re
from urllib.parse import urlparse

from vinculum.models.finding import UnifiedFinding


def generate_fingerprint(finding: UnifiedFinding) -> str:
    """
    Generate a stable fingerprint for deduplication.

    The fingerprint is based on:
    - Normalized title
    - Location key
    - Severity
    - CWE IDs (sorted)

    This allows matching findings from different tools that describe
    the same vulnerability.
    """
    components = [
        normalize_title(finding.title),
        finding.location.normalized_key(),
        finding.severity,
        "|".join(sorted(finding.cwe_ids)) if finding.cwe_ids else "",
    ]

    fingerprint_input = "::".join(components)
    return hashlib.sha256(fingerprint_input.encode()).hexdigest()[:16]


def normalize_title(title: str) -> str:
    """
    Normalize a finding title for comparison.

    - Lowercase
    - Remove special characters
    - Normalize whitespace
    - Remove common prefixes/suffixes
    """
    normalized = title.lower()

    # Remove common prefixes that vary between tools
    prefixes_to_remove = [
        "potential ",
        "possible ",
        "detected ",
        "found ",
        "vulnerability: ",
        "issue: ",
        "warning: ",
        "error: ",
    ]
    for prefix in prefixes_to_remove:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]

    # Remove special characters except spaces and hyphens
    normalized = re.sub(r"[^\w\s\-]", "", normalized)

    # Normalize whitespace
    normalized = " ".join(normalized.split())

    return normalized


def normalize_url(url: str) -> str:
    """
    Normalize a URL for comparison.

    - Remove scheme
    - Remove trailing slashes
    - Normalize path
    - Sort query parameters
    """
    try:
        parsed = urlparse(url)
        # Reconstruct without scheme
        path = parsed.path.rstrip("/") or "/"
        netloc = parsed.netloc.lower()

        # Sort query parameters if present
        query = ""
        if parsed.query:
            params = sorted(parsed.query.split("&"))
            query = "?" + "&".join(params)

        return f"{netloc}{path}{query}"
    except Exception:
        return url.lower()


def normalize_file_path(path: str) -> str:
    """
    Normalize a file path for comparison.

    - Convert to forward slashes
    - Remove leading ./
    - Lowercase on case-insensitive systems
    """
    normalized = path.replace("\\", "/")
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def extract_vulnerability_key(finding: UnifiedFinding) -> str:
    """
    Extract a key that identifies the type of vulnerability.

    This is used for grouping similar vulnerabilities regardless of location.
    """
    # Prefer CWE if available
    if finding.cwe_ids:
        return f"cwe:{sorted(finding.cwe_ids)[0]}"

    # Fall back to normalized title
    return f"title:{normalize_title(finding.title)}"


def are_similar_findings(f1: UnifiedFinding, f2: UnifiedFinding) -> bool:
    """
    Check if two findings are likely describing the same issue.

    This is a heuristic check for cases where fingerprints don't match
    but the findings might still be duplicates.
    """
    # Same CVE = definitely same issue
    if f1.cve_ids and f2.cve_ids:
        if set(f1.cve_ids) & set(f2.cve_ids):
            return True

    # Same CWE + same location = likely same issue
    if f1.cwe_ids and f2.cwe_ids:
        if set(f1.cwe_ids) & set(f2.cwe_ids):
            loc1 = f1.location.normalized_key()
            loc2 = f2.location.normalized_key()
            if loc1 == loc2:
                return True

    # Very similar titles + same severity + same location
    title1 = normalize_title(f1.title)
    title2 = normalize_title(f2.title)
    if _string_similarity(title1, title2) > 0.8:
        if f1.severity == f2.severity:
            loc1 = f1.location.normalized_key()
            loc2 = f2.location.normalized_key()
            if loc1 == loc2 or _string_similarity(loc1, loc2) > 0.7:
                return True

    return False


def _string_similarity(s1: str, s2: str) -> float:
    """
    Calculate similarity between two strings using Jaccard similarity.

    Returns a value between 0 and 1.
    """
    if not s1 or not s2:
        return 0.0

    # Convert to word sets
    words1 = set(s1.lower().split())
    words2 = set(s2.lower().split())

    if not words1 or not words2:
        return 0.0

    intersection = len(words1 & words2)
    union = len(words1 | words2)

    return intersection / union if union > 0 else 0.0
