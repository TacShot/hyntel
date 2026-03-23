from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class CVEQuery:
    keyword: str
    product_hint: str | None = None


@dataclass(frozen=True)
class AuditRule:
    identifier: str
    platform: str
    title: str
    description: str
    rationale: str
    severity: str
    check: Callable[["CommandRunner"], "CheckResult"]
    remediation: list[str]
    cve_queries: list[CVEQuery] = field(default_factory=list)


@dataclass
class CheckResult:
    rule_id: str
    status: str
    details: str
    observed_value: str | None = None
    remediation: list[str] = field(default_factory=list)
    related_cves: list[dict] = field(default_factory=list)


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class InstalledApplication:
    name: str
    version: str
    source: str


@dataclass
class ApplicationFinding:
    application: InstalledApplication
    cpe_name: str | None
    cves: list[dict] = field(default_factory=list)
