from __future__ import annotations

import json
import os
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .models import CVEQuery

NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _extract_description(cve: dict[str, Any]) -> str:
    descriptions = cve.get("descriptions", [])
    for item in descriptions:
        if item.get("lang") == "en":
            return item.get("value", "")
    return ""


def _extract_cvss(cve: dict[str, Any]) -> tuple[str | None, float | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        values = metrics.get(key)
        if not values:
            continue
        first = values[0]
        severity = first.get("cvssData", {}).get("baseSeverity") or first.get("baseSeverity")
        score = first.get("cvssData", {}).get("baseScore")
        return severity, score
    return None, None


def fetch_related_cves(
    query: CVEQuery,
    limit: int = 3,
    api_key: str | None = None,
    timeout: int = 15,
) -> list[dict[str, Any]]:
    params = {
        "keywordSearch": query.keyword,
        "resultsPerPage": str(limit),
    }
    url = f"{NVD_CVE_API}?{urlencode(params)}"
    request = Request(url, headers={"User-Agent": "security-audit-tool/0.1.0"})
    key = api_key or os.getenv("NVD_API_KEY")
    if key:
        request.add_header("apiKey", key)

    with urlopen(request, timeout=timeout) as response:
        payload = json.load(response)

    results: list[dict[str, Any]] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        severity, score = _extract_cvss(cve)
        results.append(
            {
                "id": cve.get("id"),
                "published": cve.get("published"),
                "lastModified": cve.get("lastModified"),
                "severity": severity,
                "score": score,
                "description": _extract_description(cve),
                "source": "NIST NVD",
            }
        )
    return results
