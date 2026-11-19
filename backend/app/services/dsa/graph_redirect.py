"""
PhishGuard AI - DSA Module: Graph-based Redirect Chain Analysis & Cycle Detection
Treats HTTP redirection chains as a directed graph (u -> v).
Uses Hash Set cycle detection to identify:
  - Infinite redirect loops / evasion loops
  - Shortener unrolling (bit.ly, tinyurl, etc.)
  - Cross-domain jumping & cloaking
  - Multi-hop obfuscation
"""

import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, Any, List, Set, Tuple

from backend.app.services.dsa.ssrf_guard import validate_url_for_safe_scan


URL_SHORTENERS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly", "ow.ly",
    "cutt.ly", "bitly.com", "shorturl.at", "tiny.cc", "rebrand.ly", "tr.im",
    "rb.gy", "s.id", "v.gd", "clck.ru", "shorte.st"
}


class RedirectGraphTracker:
    """
    Traces HTTP redirect paths as a directed graph.
    Uses BFS/DFS-style cycle detection with a visited Hash Set.
    """
    def __init__(self, max_hops: int = 6, timeout: float = 2.5):
        self.max_hops = max_hops
        self.timeout = timeout

    def trace_redirects(self, start_url: str) -> Dict[str, Any]:
        """
        Follows HTTP redirects step by step.
        Returns full traversal path, cycle detection flag, and cross-domain hops.
        """
        chain: List[Dict[str, Any]] = []
        visited_urls: Set[str] = set()
        visited_hosts: List[str] = []

        current_url = start_url
        has_cycle = False
        is_shortened = False

        # Check if initial host is a known shortener
        parsed_initial = urllib.parse.urlparse(start_url)
        initial_host = (parsed_initial.hostname or "").lower().lstrip("www.")
        if initial_host in URL_SHORTENERS:
            is_shortened = True

        for hop in range(self.max_hops):
            norm_current = current_url.rstrip("/")
            if norm_current in visited_urls:
                # Cycle / Loop detected in redirect graph!
                has_cycle = True
                chain.append({
                    "hop": hop + 1,
                    "url": current_url,
                    "status_code": 310,  # ERR_TOO_MANY_REDIRECTS
                    "is_loop": True
                })
                break

            visited_urls.add(norm_current)
            parsed = urllib.parse.urlparse(current_url)
            host = (parsed.hostname or "").lower()
            visited_hosts.append(host)

            # SSRF & Network Safety Pre-Flight Verification (Phase 5)
            is_safe, resolved_ip, block_reason = validate_url_for_safe_scan(current_url)
            if not is_safe:
                chain.append({
                    "hop": hop + 1,
                    "url": current_url,
                    "status_code": None,
                    "ssrf_blocked": True,
                    "error": f"SSRF Blocked: {block_reason}",
                    "is_loop": False
                })
                break

            try:
                # Custom HTTP request without auto-following redirects so we can record each graph node
                class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        # Do not auto follow; let us catch the header manually
                        return None

                opener = urllib.request.build_opener(NoRedirectHandler)
                req = urllib.request.Request(
                    current_url,
                    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PhishGuardAI-GraphTracker/2.0"}
                )

                try:
                    with opener.open(req, timeout=self.timeout) as resp:
                        status_code = resp.status
                        chain.append({
                            "hop": hop + 1,
                            "url": current_url,
                            "status_code": status_code,
                            "is_loop": False
                        })
                        # Reached terminal destination (200 OK or non-redirect)
                        break
                except urllib.error.HTTPError as e:
                    # 301, 302, 303, 307, 308 redirects trigger HTTPError in NoRedirectHandler
                    if e.code in (301, 302, 303, 307, 308):
                        location = e.headers.get("Location")
                        chain.append({
                            "hop": hop + 1,
                            "url": current_url,
                            "status_code": e.code,
                            "redirect_to": location,
                            "is_loop": False
                        })
                        if not location:
                            break
                        # Handle relative redirects
                        current_url = urllib.parse.urljoin(current_url, location)
                    else:
                        chain.append({
                            "hop": hop + 1,
                            "url": current_url,
                            "status_code": e.code,
                            "error": str(e),
                            "is_loop": False
                        })
                        break
            except Exception as e:
                chain.append({
                    "hop": hop + 1,
                    "url": current_url,
                    "status_code": None,
                    "error": str(e)[:100],
                    "is_loop": False
                })
                break

        final_url = chain[-1]["url"] if chain else start_url
        parsed_final = urllib.parse.urlparse(final_url)
        final_host = (parsed_final.hostname or "").lower().lstrip("www.")

        # Check cross-domain jumping
        is_cross_domain = False
        if len(visited_hosts) > 1 and initial_host and final_host:
            is_cross_domain = (initial_host != final_host)

        return {
            "initial_url": start_url,
            "final_url": final_url,
            "hop_count": len(chain) - 1 if len(chain) > 0 else 0,
            "chain": chain,
            "has_redirect_loop": has_cycle,
            "is_cross_domain": is_cross_domain,
            "is_url_shortener": is_shortened,
            "visited_hosts": list(dict.fromkeys(visited_hosts))
        }
