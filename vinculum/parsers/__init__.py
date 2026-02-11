"""Parsers for various security tool output formats."""

from vinculum.parsers.base import BaseParser, ParseError, ParserRegistry
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

__all__ = [
    "BaseParser",
    "ParseError",
    "ParserRegistry",
    "AriadneParser",
    "AriadneReportParser",
    "BurpParser",
    "BypassBurritoParser",
    "CepheusParser",
    "CheckovParser",
    "DependencyCheckParser",
    "GrypeParser",
    "IndagoParser",
    "MobilicustosParser",
    "MobSFParser",
    "NessusParser",
    "NiktoParser",
    "NmapParser",
    "NubicustosParser",
    "NubicustosContainersParser",
    "NucleiParser",
    "ReticustosParser",
    "ReticustosEndpointsParser",
    "SemgrepParser",
    "SnykParser",
    "TrivyParser",
    "ZAPParser",
]
