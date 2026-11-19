"""
PhishGuard AI - Threat Intelligence Integration Engine (Phase 4)
Integrates real, optional, time-bounded, and observable threat intelligence feeds:
  1. VirusTotal API v3 (URL reputation analysis)
  2. Google Safe Browsing API v4 (threatMatches check)
  3. AbuseIPDB API v2 (IP reputation check)

Key Guarantees:
  - Real & Optional: Operates only when valid API keys are configured; otherwise reports NOT_CONFIGURED.
  - Time-Bounded: Strict 2.0s network timeout per feed.
  - Observable: Clear attribution per feed in scan results and audit logs.
  - TTL Caching: 1-hour cache per URL to conserve API rate limits.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import logging
import time
from typing import Dict, Any, List, Optional, Tuple
import urllib.parse

import httpx

from backend.app.core.config import settings

logger = logging.getLogger("phishguard.threat_intel")


class FeedStatus(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    CLEAN = "CLEAN"
    THREAT_DETECTED = "THREAT_DETECTED"
    CACHE_HIT = "CACHE_HIT"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    AUTH_ERROR = "AUTH_ERROR"
    ERROR = "ERROR"


@dataclass
class ThreatFinding:
    rule_id: str
    title: str
    reason: str
    severity: str  # HIGH, CRITICAL
    weight: int
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "reason": self.reason,
            "severity": self.severity,
            "weight": self.weight,
            "source": self.source,
            "metadata": self.metadata,
            "layer": "L1_THREAT_INTEL"
        }


class ThreatIntelService:
    def __init__(self, cache_ttl_seconds: int = 3600):
        self.cache_ttl = cache_ttl_seconds
        # In-memory TTL cache: key -> (timestamp, List[ThreatFinding], Dict[str, str])
        self._cache: Dict[str, Tuple[float, List[ThreatFinding], Dict[str, str]]] = {}
        self.timeout = float(getattr(settings, "LAYER_TIMEOUT_SECONDS", 2.0))

    def _get_cache_key(self, url: str) -> str:
        return hashlib.sha256(url.strip().lower().encode("utf-8")).hexdigest()

    def _get_from_cache(self, url: str) -> Optional[Tuple[List[ThreatFinding], Dict[str, str]]]:
        key = self._get_cache_key(url)
        if key in self._cache:
            ts, findings, statuses = self._cache[key]
            if (time.time() - ts) < self.cache_ttl:
                hit_statuses = {k: FeedStatus.CACHE_HIT.value for k in statuses}
                return findings, hit_statuses
            else:
                del self._cache[key]
        return None

    def _put_into_cache(self, url: str, findings: List[ThreatFinding], statuses: Dict[str, str]) -> None:
        key = self._get_cache_key(url)
        self._cache[key] = (time.time(), findings, statuses)

    def query_virustotal(self, url: str) -> Tuple[Optional[ThreatFinding], FeedStatus]:
        """Query VirusTotal v3 API for URL reputation if configured."""
        api_key = settings.VIRUSTOTAL_API_KEY
        if not api_key:
            return None, FeedStatus.NOT_CONFIGURED

        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": api_key, "Accept": "application/json"}

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(endpoint, headers=headers)
                if res.status_code == 200:
                    data = res.json().get("data", {}).get("attributes", {})
                    stats = data.get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    total = sum(stats.values()) or 1

                    if malicious >= 2:
                        return ThreatFinding(
                            rule_id="TI_VIRUSTOTAL_MALICIOUS",
                            title="VirusTotal Threat Detection",
                            reason=f"Flagged as malicious by {malicious}/{total} security vendors on VirusTotal.",
                            severity="CRITICAL",
                            weight=40,
                            source="VIRUSTOTAL",
                            metadata={"malicious_vendors": malicious, "suspicious_vendors": suspicious, "total_vendors": total}
                        ), FeedStatus.THREAT_DETECTED
                    elif malicious == 1 or suspicious >= 2:
                        return ThreatFinding(
                            rule_id="TI_VIRUSTOTAL_SUSPICIOUS",
                            title="VirusTotal Suspicious Activity",
                            reason=f"Flagged as suspicious by security vendors on VirusTotal ({malicious} malicious, {suspicious} suspicious).",
                            severity="HIGH",
                            weight=25,
                            source="VIRUSTOTAL",
                            metadata={"malicious_vendors": malicious, "suspicious_vendors": suspicious}
                        ), FeedStatus.THREAT_DETECTED
                    return None, FeedStatus.CLEAN

                elif res.status_code == 404:
                    return None, FeedStatus.CLEAN  # URL not seen before
                elif res.status_code == 429:
                    return None, FeedStatus.RATE_LIMITED
                elif res.status_code in (401, 403):
                    return None, FeedStatus.AUTH_ERROR
                else:
                    return None, FeedStatus.ERROR
        except httpx.TimeoutException:
            return None, FeedStatus.TIMEOUT
        except Exception as e:
            logger.warning(f"VirusTotal query error for {url}: {e}")
            return None, FeedStatus.ERROR

    def query_google_safebrowsing(self, url: str) -> Tuple[Optional[ThreatFinding], FeedStatus]:
        """Query Google Safe Browsing v4 ThreatMatches API if configured."""
        api_key = settings.GOOGLE_SAFE_BROWSING_KEY
        if not api_key:
            return None, FeedStatus.NOT_CONFIGURED

        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
        payload = {
            "client": {"clientId": "phishguard-ai", "clientVersion": "2.0.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.post(endpoint, json=payload)
                if res.status_code == 200:
                    matches = res.json().get("matches", [])
                    if matches:
                        threat_types = [m.get("threatType") for m in matches]
                        return ThreatFinding(
                            rule_id="TI_GOOGLE_SAFEBROWSING_HIT",
                            title="Google Safe Browsing Match",
                            reason=f"Identified as malicious by Google Safe Browsing: {', '.join(threat_types)}.",
                            severity="CRITICAL",
                            weight=45,
                            source="GOOGLE_SAFE_BROWSING",
                            metadata={"threat_types": threat_types}
                        ), FeedStatus.THREAT_DETECTED
                    return None, FeedStatus.CLEAN
                elif res.status_code == 429:
                    return None, FeedStatus.RATE_LIMITED
                elif res.status_code in (400, 403):
                    return None, FeedStatus.AUTH_ERROR
                else:
                    return None, FeedStatus.ERROR
        except httpx.TimeoutException:
            return None, FeedStatus.TIMEOUT
        except Exception as e:
            logger.warning(f"Google Safe Browsing query error for {url}: {e}")
            return None, FeedStatus.ERROR

    def query_abuseipdb(self, host_or_ip: str) -> Tuple[Optional[ThreatFinding], FeedStatus]:
        """Query AbuseIPDB API v2 check endpoint if configured and destination is an IP."""
        api_key = settings.ABUSEIPDB_API_KEY
        if not api_key:
            return None, FeedStatus.NOT_CONFIGURED

        parsed = urllib.parse.urlparse(host_or_ip) if "://" in host_or_ip else None
        target = (parsed.hostname if parsed else host_or_ip).strip("[]")
        
        # AbuseIPDB is strictly for IP addresses
        import ipaddress
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return None, FeedStatus.CLEAN

        endpoint = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": target, "maxAgeInDays": 90}

        try:
            with httpx.Client(timeout=self.timeout) as client:
                res = client.get(endpoint, headers=headers, params=params)
                if res.status_code == 200:
                    data = res.json().get("data", {})
                    score = data.get("abuseConfidenceScore", 0)
                    total_reports = data.get("totalReports", 0)
                    if score >= 50:
                        return ThreatFinding(
                            rule_id="TI_ABUSEIPDB_MALICIOUS_IP",
                            title="AbuseIPDB Malicious Host",
                            reason=f"Host IP has high abuse confidence score ({score}%) across {total_reports} reports on AbuseIPDB.",
                            severity="CRITICAL" if score >= 80 else "HIGH",
                            weight=35 if score >= 80 else 20,
                            source="ABUSEIPDB",
                            metadata={"abuse_score": score, "total_reports": total_reports}
                        ), FeedStatus.THREAT_DETECTED
                    return None, FeedStatus.CLEAN
                elif res.status_code == 429:
                    return None, FeedStatus.RATE_LIMITED
                elif res.status_code in (401, 403):
                    return None, FeedStatus.AUTH_ERROR
                else:
                    return None, FeedStatus.ERROR
        except httpx.TimeoutException:
            return None, FeedStatus.TIMEOUT
        except Exception as e:
            logger.warning(f"AbuseIPDB query error for {target}: {e}")
            return None, FeedStatus.ERROR

    def scan_threat_feeds(self, url: str) -> Tuple[List[ThreatFinding], Dict[str, str]]:
        """
        Coordinates threat feed queries with caching and structured attribution.
        Returns: (findings_list, feed_statuses_dict)
        """
        cached = self._get_from_cache(url)
        if cached is not None:
            return cached

        findings: List[ThreatFinding] = []
        statuses: Dict[str, str] = {}

        # 1. VirusTotal
        vt_finding, vt_status = self.query_virustotal(url)
        statuses["virustotal"] = vt_status.value
        if vt_finding:
            findings.append(vt_finding)

        # 2. Google Safe Browsing
        gsb_finding, gsb_status = self.query_google_safebrowsing(url)
        statuses["google_safebrowsing"] = gsb_status.value
        if gsb_finding:
            findings.append(gsb_finding)

        # 3. AbuseIPDB
        abuse_finding, abuse_status = self.query_abuseipdb(url)
        statuses["abuseipdb"] = abuse_status.value
        if abuse_finding:
            findings.append(abuse_finding)

        self._put_into_cache(url, findings, statuses)
        return findings, statuses


# Global threat intelligence service instance
threat_intel_service = ThreatIntelService()
