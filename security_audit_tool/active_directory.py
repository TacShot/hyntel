"""Read-only Active Directory domain configuration checks (Windows only)."""
from __future__ import annotations

import json
import platform
import subprocess
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ADCheck:
    check_id: str
    status: str
    title: str
    details: str
    observed: str | None = None
    recommendation: str | None = None


@dataclass
class ActiveDirectoryResult:
    supported: bool
    domain_joined: bool | None
    domain: str | None
    checks: list[ADCheck]
    warnings: list[str]


def verify_active_directory_config(target_os: str | None = None) -> ActiveDirectoryResult:
    """Verify discoverable AD posture; never changes domain or policy settings."""
    target = target_os or platform.system().lower()
    if target not in {"windows", "win32"}:
        return ActiveDirectoryResult(False, None, None, [], ["Active Directory verification is supported on Windows hosts only."])
    script = r"""
$ErrorActionPreference='Stop'
$cs=Get-CimInstance Win32_ComputerSystem
$domain=$null
$domainInfo=$null
$forestInfo=$null
$dc=$null
$pwdPolicy=$null
$lockout=$null
$moduleAvailable=$false
if ($cs.PartOfDomain) {
  $domain=[string]$cs.Domain
  if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory -ErrorAction Stop
    $moduleAvailable=$true
    $domainInfo=Get-ADDomain
    $forestInfo=Get-ADForest
    $pwdPolicy=Get-ADDefaultDomainPasswordPolicy
    $lockout=[pscustomobject]@{LockedOutThreshold=$pwdPolicy.LockoutThreshold;ObservationWindow=$pwdPolicy.LockoutObservationWindow;Duration=$pwdPolicy.LockoutDuration}
  }
  try { $dc=(nltest /dsgetdc:$domain 2>&1 | Out-String).Trim() } catch { $dc=$_.Exception.Message }
}
[pscustomobject]@{
  PartOfDomain=[bool]$cs.PartOfDomain; Domain=$domain; ModuleAvailable=$moduleAvailable;
  DomainFunctionalLevel=if($domainInfo){[string]$domainInfo.DomainMode}else{$null};
  ForestFunctionalLevel=if($forestInfo){[string]$forestInfo.ForestMode}else{$null};
  DomainSID=if($domainInfo){[string]$domainInfo.DomainSID}else{$null};
  PDCEmulator=if($domainInfo){[string]$domainInfo.PDCEmulator}else{$null};
  PasswordMinLength=if($pwdPolicy){[int]$pwdPolicy.MinPasswordLength}else{$null};
  PasswordMaxAge=if($pwdPolicy){[string]$pwdPolicy.MaxPasswordAge}else{$null};
  PasswordComplexity=if($pwdPolicy){[bool]$pwdPolicy.ComplexityEnabled}else{$null};
  ReversibleEncryption=if($pwdPolicy){[bool]$pwdPolicy.ReversibleEncryptionEnabled}else{$null};
  LockoutThreshold=if($pwdPolicy){[int]$pwdPolicy.LockoutThreshold}else{$null};
  DCDiscovery=$dc
} | ConvertTo-Json -Depth 4 -Compress
"""
    try:
        proc = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                              capture_output=True, text=True, check=False, shell=False, timeout=35)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return ActiveDirectoryResult(True, None, None, [], [f"Could not query Windows domain state: {exc}"])
    if proc.returncode != 0:
        return ActiveDirectoryResult(True, None, None, [], [(proc.stderr or proc.stdout or "PowerShell query failed").strip()[:1500]])
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return ActiveDirectoryResult(True, None, None, [], [f"Invalid PowerShell JSON response: {exc}"])
    if not data.get("PartOfDomain"):
        return ActiveDirectoryResult(True, False, None, [
            ADCheck("ad_domain_join", "skip", "Host is not joined to an Active Directory domain",
                    "This machine is not domain joined; domain policy checks are not applicable.")
        ], [])
    checks: list[ADCheck] = [
        ADCheck("ad_domain_join", "pass", "Domain membership detected", "Host reports membership in an AD domain.", data.get("Domain")),
        ADCheck("ad_dc_discovery", "pass" if data.get("DCDiscovery") and "DC:" in data["DCDiscovery"] else "warn",
                "Domain controller discovery", "Validate that the host can locate a domain controller.",
                str(data.get("DCDiscovery") or "No discovery result"),
                "Check DNS SRV records, network connectivity, time synchronization, and site configuration."),
    ]
    if not data.get("ModuleAvailable"):
        return ActiveDirectoryResult(True, True, data.get("Domain"), checks,
            ["RSAT ActiveDirectory PowerShell module is not installed; domain/forest functional level and password policy checks could not be read."])
    def add(check_id: str, title: str, ok: bool, detail: str, observed: Any, recommendation: str) -> None:
        checks.append(ADCheck(check_id, "pass" if ok else "fail", title, detail, str(observed), None if ok else recommendation))
    min_len = data.get("PasswordMinLength")
    add("ad_password_min_length", "Domain minimum password length", isinstance(min_len, int) and min_len >= 14,
        "Baseline threshold: at least 14 characters (adjust to organizational policy).", min_len,
        "Review the domain password policy and align the minimum length with your approved baseline.")
    complexity = data.get("PasswordComplexity")
    add("ad_password_complexity", "Domain password complexity", complexity is True,
        "Checks the default domain password complexity setting.", complexity,
        "Enable password complexity if required by the organization's identity security baseline.")
    reversible = data.get("ReversibleEncryption")
    add("ad_reversible_password_storage", "Reversible password encryption disabled", reversible is False,
        "Reversible password storage should remain disabled.", reversible,
        "Disable reversible password encryption; investigate accounts or policies that require it.")
    threshold = data.get("LockoutThreshold")
    add("ad_account_lockout_threshold", "Account lockout threshold configured", isinstance(threshold, int) and 1 <= threshold <= 10,
        "Review threshold against the organization's lockout and denial-of-service risk policy.", threshold,
        "Set a documented lockout threshold and observation duration consistent with the organization's policy.")
    return ActiveDirectoryResult(True, True, data.get("Domain"), checks, [])


def result_to_dict(result: ActiveDirectoryResult) -> dict[str, Any]:
    return {"supported": result.supported, "domain_joined": result.domain_joined, "domain": result.domain,
            "checks": [asdict(check) for check in result.checks], "warnings": result.warnings}
