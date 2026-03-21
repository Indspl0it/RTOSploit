"""NVD API client for fetching CVE data."""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
import urllib.parse
from typing import Optional

from rtosploit.cve.database import CVEEntry

logger = logging.getLogger(__name__)

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDClient:
    """Client for the NIST NVD 2.0 REST API.

    Rate limits:
        - Without API key: 5 requests per 30 seconds (~6/min)
        - With API key: 50 requests per 30 seconds
    """

    def __init__(self, api_key: Optional[str] = None) -> None:
        self._api_key = api_key
        self._last_request_time: float = 0.0
        # Minimum interval between requests (seconds)
        self._min_interval = 1.2 if api_key else 6.0

    def _rate_limit(self) -> None:
        """Block until enough time has passed since the last request."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self._min_interval:
            time.sleep(self._min_interval - elapsed)

    _MAX_RETRIES = 3

    def _request(self, url: str) -> dict:
        """Make a rate-limited GET request to the NVD API.

        Retries on HTTP 429 (with exponential backoff) and transient 5xx errors.
        """
        self._rate_limit()
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "RTOSploit-CVECorrelator/1.0")
        if self._api_key:
            req.add_header("apiKey", self._api_key)

        last_exc: Exception | None = None
        for attempt in range(self._MAX_RETRIES):
            logger.debug("NVD request (attempt %d): %s", attempt + 1, url)
            self._last_request_time = time.time()
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                last_exc = exc
                if exc.code == 429:
                    # Too Many Requests — honour Retry-After or exponential backoff
                    retry_after = exc.headers.get("Retry-After") if exc.headers else None
                    if retry_after is not None:
                        try:
                            delay = float(retry_after)
                        except (ValueError, TypeError):
                            delay = 2.0 ** (attempt + 1)
                    else:
                        delay = 2.0 ** (attempt + 1)  # 2s, 4s, 8s
                    logger.warning(
                        "NVD 429 Too Many Requests, retrying in %.1fs", delay
                    )
                    time.sleep(delay)
                    continue
                if exc.code in (500, 502, 503) and attempt == 0:
                    # Transient server error — retry once with 2s delay
                    logger.warning(
                        "NVD server error %d, retrying in 2s", exc.code
                    )
                    time.sleep(2.0)
                    continue
                # Non-retryable 4xx or exhausted server-error retry — raise
                raise

        # Exhausted all retries (only reachable for 429 loops)
        raise last_exc  # type: ignore[misc]

    @staticmethod
    def _parse_nvd_item(item: dict) -> CVEEntry:
        """Parse a single NVD CVE item into a CVEEntry."""
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "")

        # Description — prefer English
        descriptions = cve_data.get("descriptions", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # CVSS score and severity — try 3.1, then 3.0, then 2.0
        cvss_score: Optional[float] = None
        severity = "medium"
        metrics = cve_data.get("metrics", {})
        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                base_severity = metric_list[0].get("baseSeverity", "").lower()
                if not base_severity:
                    base_severity = cvss_data.get("baseSeverity", "").lower()
                if base_severity:
                    severity = base_severity
                break

        # References
        references = [
            ref.get("url", "")
            for ref in cve_data.get("references", [])
            if ref.get("url")
        ]

        # Published date
        published_date = cve_data.get("published", "")[:10]  # YYYY-MM-DD

        return CVEEntry(
            cve_id=cve_id,
            description=description,
            cvss_score=cvss_score,
            severity=severity,
            affected_product="",  # Caller should set based on search context
            affected_versions=[],
            references=references,
            published_date=published_date,
            has_exploit=False,
        )

    def search_cves(
        self, keyword: str, product: Optional[str] = None
    ) -> list[CVEEntry]:
        """Search NVD for CVEs matching a keyword and optional product name.

        Returns a list of CVEEntry objects parsed from the NVD response.
        """
        params: dict[str, str] = {"keywordSearch": keyword}
        if product:
            params["keywordSearch"] = f"{keyword} {product}"
        params["resultsPerPage"] = "50"

        url = f"{NVD_API_BASE}?{urllib.parse.urlencode(params)}"
        data = self._request(url)

        entries: list[CVEEntry] = []
        for vuln in data.get("vulnerabilities", []):
            entry = self._parse_nvd_item(vuln)
            if product:
                entry.affected_product = product.lower()
            entries.append(entry)
        return entries

    def fetch_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """Fetch a single CVE by its ID (e.g. 'CVE-2021-43997')."""
        url = f"{NVD_API_BASE}?cveId={urllib.parse.quote(cve_id)}"
        data = self._request(url)
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            return None
        return self._parse_nvd_item(vulns[0])
