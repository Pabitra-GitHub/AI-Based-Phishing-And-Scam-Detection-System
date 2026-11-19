"""Unit tests for Phase 4 Threat Intelligence Integration Engine.
Verifies real, optional, time-bounded, and observable threat intelligence behavior.
"""
from unittest.mock import patch, MagicMock
import time
import httpx
import pytest

from backend.app.services.threat_intelligence import (
    ThreatIntelService,
    FeedStatus,
    threat_intel_service,
)
from backend.app.core.config import settings


def test_unconfigured_feeds_report_not_configured():
    """When no API keys are provided, feeds must explicitly report NOT_CONFIGURED."""
    svc = ThreatIntelService()
    with patch.object(settings, "VIRUSTOTAL_API_KEY", None), \
         patch.object(settings, "GOOGLE_SAFE_BROWSING_KEY", None), \
         patch.object(settings, "ABUSEIPDB_API_KEY", None):
        findings, statuses = svc.scan_threat_feeds("http://example.com")
        assert findings == []
        assert statuses["virustotal"] == FeedStatus.NOT_CONFIGURED.value
        assert statuses["google_safebrowsing"] == FeedStatus.NOT_CONFIGURED.value
        assert statuses["abuseipdb"] == FeedStatus.NOT_CONFIGURED.value


def test_virustotal_malicious_detection_and_attribution():
    """Mock VirusTotal returning 5 malicious vendors."""
    svc = ThreatIntelService()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 1,
                    "harmless": 60,
                    "undetected": 10
                }
            }
        }
    }

    with patch.object(settings, "VIRUSTOTAL_API_KEY", "dummy_vt_key"), \
         patch("httpx.Client.get", return_value=mock_resp):
        finding, status = svc.query_virustotal("http://evil-phish.xyz")
        assert status == FeedStatus.THREAT_DETECTED
        assert finding is not None
        assert finding.rule_id == "TI_VIRUSTOTAL_MALICIOUS"
        assert finding.severity == "CRITICAL"
        assert finding.source == "VIRUSTOTAL"
        assert "5/76" in finding.reason


def test_google_safebrowsing_detection():
    """Mock Google Safe Browsing reporting a SOCIAL_ENGINEERING match."""
    svc = ThreatIntelService()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
                "threat": {"url": "http://evil-login.xyz"}
            }
        ]
    }

    with patch.object(settings, "GOOGLE_SAFE_BROWSING_KEY", "dummy_gsb_key"), \
         patch("httpx.Client.post", return_value=mock_resp):
        finding, status = svc.query_google_safebrowsing("http://evil-login.xyz")
        assert status == FeedStatus.THREAT_DETECTED
        assert finding is not None
        assert finding.rule_id == "TI_GOOGLE_SAFEBROWSING_HIT"
        assert "SOCIAL_ENGINEERING" in finding.reason


def test_abuseipdb_rate_limiting_handling():
    """Verify AbuseIPDB handling HTTP 429 rate limit safely."""
    svc = ThreatIntelService()
    mock_resp = MagicMock()
    mock_resp.status_code = 429

    with patch.object(settings, "ABUSEIPDB_API_KEY", "dummy_abuse_key"), \
         patch("httpx.Client.get", return_value=mock_resp):
        finding, status = svc.query_abuseipdb("http://198.51.100.1")
        assert status == FeedStatus.RATE_LIMITED
        assert finding is None


def test_feed_timeout_handling():
    """Verify timeout exception results in TIMEOUT status without crashing."""
    svc = ThreatIntelService()
    with patch.object(settings, "VIRUSTOTAL_API_KEY", "dummy_vt_key"), \
         patch("httpx.Client.get", side_effect=httpx.TimeoutException("Connection timed out")):
        finding, status = svc.query_virustotal("http://slow-site.com")
        assert status == FeedStatus.TIMEOUT
        assert finding is None


def test_ttl_cache_expiration():
    """Verify cached items are returned within TTL and expire after TTL."""
    svc = ThreatIntelService(cache_ttl_seconds=1)
    with patch.object(settings, "VIRUSTOTAL_API_KEY", None), \
         patch.object(settings, "GOOGLE_SAFE_BROWSING_KEY", None), \
         patch.object(settings, "ABUSEIPDB_API_KEY", None):
        
        # 1. First query populates cache
        _, statuses1 = svc.scan_threat_feeds("http://cache-test.org")
        assert statuses1["virustotal"] == FeedStatus.NOT_CONFIGURED.value

        # 2. Second immediate query hits cache
        _, statuses2 = svc.scan_threat_feeds("http://cache-test.org")
        assert statuses2["virustotal"] == FeedStatus.CACHE_HIT.value

        # 3. Simulate cache expiration by updating stored timestamp
        key = svc._get_cache_key("http://cache-test.org")
        svc._cache[key] = (time.time() - 10, [], statuses1)

        # 4. Next query re-fetches
        _, statuses3 = svc.scan_threat_feeds("http://cache-test.org")
        assert statuses3["virustotal"] == FeedStatus.NOT_CONFIGURED.value


def test_benign_edge_cases_no_false_alarm():
    """Verify clean response when external feed returns 0 malicious detections."""
    svc = ThreatIntelService()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 5
                }
            }
        }
    }

    with patch.object(settings, "VIRUSTOTAL_API_KEY", "dummy_vt_key"), \
         patch("httpx.Client.get", return_value=mock_resp):
        finding, status = svc.query_virustotal("https://google.com")
        assert status == FeedStatus.CLEAN
        assert finding is None
