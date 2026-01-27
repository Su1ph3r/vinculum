"""AI-powered correlation for semantic matching of findings."""

import json
import os
from abc import ABC, abstractmethod

from vinculum.models.finding import UnifiedFinding


class BaseAICorrelator(ABC):
    """Abstract base class for AI correlators."""

    @abstractmethod
    def are_same_issue(self, finding1: UnifiedFinding, finding2: UnifiedFinding) -> bool:
        """Determine if two findings describe the same security issue."""
        ...

    def _build_comparison_prompt(
        self, finding1: UnifiedFinding, finding2: UnifiedFinding
    ) -> str:
        """Build a prompt for comparing two findings."""
        return f"""You are a security expert analyzing vulnerability findings from different tools.
Determine if these two findings describe the SAME security vulnerability.

Finding 1 (from {finding1.source_tool}):
- Title: {finding1.title}
- Severity: {finding1.severity}
- CWE: {', '.join(finding1.cwe_ids) or 'None'}
- CVE: {', '.join(finding1.cve_ids) or 'None'}
- Location: {finding1.location.normalized_key()}
- Description: {finding1.short_description(200)}

Finding 2 (from {finding2.source_tool}):
- Title: {finding2.title}
- Severity: {finding2.severity}
- CWE: {', '.join(finding2.cwe_ids) or 'None'}
- CVE: {', '.join(finding2.cve_ids) or 'None'}
- Location: {finding2.location.normalized_key()}
- Description: {finding2.short_description(200)}

Are these findings describing the SAME security vulnerability?
Respond with ONLY "yes" or "no"."""


class ClaudeCorrelator(BaseAICorrelator):
    """AI correlator using Anthropic Claude API."""

    def __init__(self, api_key: str | None = None, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.model = model
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                from anthropic import Anthropic

                self._client = Anthropic(api_key=self.api_key)
            except ImportError:
                raise ImportError("anthropic package required: pip install anthropic")
        return self._client

    def are_same_issue(self, finding1: UnifiedFinding, finding2: UnifiedFinding) -> bool:
        prompt = self._build_comparison_prompt(finding1, finding2)
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=10,
                messages=[{"role": "user", "content": prompt}],
            )
            answer = response.content[0].text.strip().lower()
            return answer == "yes"
        except Exception:
            return False


class OpenAICorrelator(BaseAICorrelator):
    """AI correlator using OpenAI API."""

    def __init__(self, api_key: str | None = None, model: str = "gpt-4o-mini"):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.model = model
        self._client = None

    @property
    def client(self):
        if self._client is None:
            try:
                from openai import OpenAI

                self._client = OpenAI(api_key=self.api_key)
            except ImportError:
                raise ImportError("openai package required: pip install openai")
        return self._client

    def are_same_issue(self, finding1: UnifiedFinding, finding2: UnifiedFinding) -> bool:
        prompt = self._build_comparison_prompt(finding1, finding2)
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                max_tokens=10,
                messages=[{"role": "user", "content": prompt}],
            )
            answer = response.choices[0].message.content.strip().lower()
            return answer == "yes"
        except Exception:
            return False


class OllamaCorrelator(BaseAICorrelator):
    """AI correlator using local Ollama instance."""

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3.2"):
        self.base_url = base_url.rstrip("/")
        self.model = model

    def are_same_issue(self, finding1: UnifiedFinding, finding2: UnifiedFinding) -> bool:
        prompt = self._build_comparison_prompt(finding1, finding2)
        try:
            import httpx

            response = httpx.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"num_predict": 10},
                },
                timeout=30.0,
            )
            response.raise_for_status()
            answer = response.json().get("response", "").strip().lower()
            return answer == "yes"
        except Exception:
            return False


class LMStudioCorrelator(BaseAICorrelator):
    """AI correlator using local LM Studio instance (OpenAI-compatible API)."""

    def __init__(self, base_url: str = "http://localhost:1234/v1", model: str = "local-model"):
        self.base_url = base_url.rstrip("/")
        self.model = model

    def are_same_issue(self, finding1: UnifiedFinding, finding2: UnifiedFinding) -> bool:
        prompt = self._build_comparison_prompt(finding1, finding2)
        try:
            import httpx

            response = httpx.post(
                f"{self.base_url}/chat/completions",
                json={
                    "model": self.model,
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 10,
                },
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()
            answer = data["choices"][0]["message"]["content"].strip().lower()
            return answer == "yes"
        except Exception:
            return False


def get_ai_correlator(
    provider: str,
    api_key: str | None = None,
    model: str | None = None,
    base_url: str | None = None,
) -> BaseAICorrelator:
    """
    Factory function to get an AI correlator by provider name.

    Args:
        provider: Provider name (claude, openai, ollama, lmstudio)
        api_key: API key for cloud providers
        model: Model name to use
        base_url: Base URL for local providers

    Returns:
        Configured AI correlator instance
    """
    provider = provider.lower()

    if provider == "claude":
        kwargs = {}
        if api_key:
            kwargs["api_key"] = api_key
        if model:
            kwargs["model"] = model
        return ClaudeCorrelator(**kwargs)

    elif provider == "openai":
        kwargs = {}
        if api_key:
            kwargs["api_key"] = api_key
        if model:
            kwargs["model"] = model
        return OpenAICorrelator(**kwargs)

    elif provider == "ollama":
        kwargs = {}
        if base_url:
            kwargs["base_url"] = base_url
        if model:
            kwargs["model"] = model
        return OllamaCorrelator(**kwargs)

    elif provider == "lmstudio":
        kwargs = {}
        if base_url:
            kwargs["base_url"] = base_url
        if model:
            kwargs["model"] = model
        return LMStudioCorrelator(**kwargs)

    else:
        raise ValueError(f"Unknown AI provider: {provider}")
