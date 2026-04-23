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


@dataclass
class OsInfo:
    """Detected operating system information for the current host."""

    name: str
    version: str
    architecture: str | None = None
    build: str | None = None
    kernel: str | None = None
    security_patches: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class DriverInfo:
    """Information about a single device driver's signing status."""

    name: str
    provider: str
    signer: str | None
    # "microsoft" | "whql" | "custom" | "unsigned"
    sign_type: str
    is_signed: bool
    is_suspicious: bool
    is_dangerous: bool
    inf_name: str | None = None


@dataclass(frozen=True)
class RunningProcess:
    pid: int
    name: str
    executable: str | None = None
    command_line: str | None = None
    source: str = "process-list"


@dataclass
class ProcessFinding:
    process: RunningProcess
    severity: str
    reasons: list[str] = field(default_factory=list)
    recommended_action: str | None = None
