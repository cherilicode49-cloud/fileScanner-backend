import re
import logging
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
import httpx
from bs4 import BeautifulSoup
from app.config import settings
from app.utils.security_utils import validate_url_security
from app.services.yara_service import yara_service

logger = logging.getLogger(__name__)

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "account", "banking", "wallet", "secure", "update",
    "password", "credential", "confirm", "signin", "authenticate", "paypal",
    "apple", "microsoft", "google"
]

MALICIOUS_DOWNLOAD_EXTENSIONS = [
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".apk", ".iso", ".dmg"
]


class URLService:
    def __init__(self):
        self.timeout = settings.URL_SCAN_TIMEOUT
        self.max_redirects = settings.URL_MAX_REDIRECTS
        self.max_size = settings.max_url_content_bytes

    def analyze_url(self, target_url: str) -> Dict[str, Any]:
        """
        Conducts comprehensive local security analysis on a URL.
        1. SSRF and DNS security check
        2. Structural and lexical indicators
        3. Safe HTTP retrieval following redirects with SSRF check at each hop
        4. HTML and metadata inspection
        5. YARA scanning on response payload
        """
        threats: List[Dict[str, Any]] = []
        indicators: Dict[str, Any] = {}
        redirect_chain: List[str] = [target_url]
        current_url = target_url

        # 1. Initial URL validation & SSRF Check
        is_safe, error_msg, meta = validate_url_security(current_url)
        if not is_safe:
            return {
                "status": "MALICIOUS" if "SSRF" in (error_msg or "") else "ERROR",
                "url": target_url,
                "final_url": None,
                "https_supported": target_url.lower().startswith("https"),
                "redirect_count": 0,
                "redirect_chain": [target_url],
                "security_indicators": {"error": error_msg},
                "threats": [
                    {
                        "scanner_name": "url_security",
                        "threat_name": "SSRF_Blocked" if "SSRF" in (error_msg or "") else "Invalid_URL",
                        "threat_category": "ssrf_violation" if "SSRF" in (error_msg or "") else "invalid_input",
                        "severity": "CRITICAL" if "SSRF" in (error_msg or "") else "HIGH",
                        "description": error_msg
                    }
                ],
                "scanner_results": {
                    "url_analyzer": {"status": "MALICIOUS" if "SSRF" in (error_msg or "") else "ERROR", "error": error_msg}
                }
            }

        indicators["initial_ip_addresses"] = meta.get("resolved_ips", [])
        indicators["is_ip_based_url"] = meta.get("is_ip_host", False)
        indicators["is_punycode_homograph"] = meta.get("is_punycode", False)
        indicators["is_url_shortener"] = meta.get("is_shortener", False)

        if indicators["is_ip_based_url"]:
            threats.append({
                "scanner_name": "url_analyzer",
                "threat_name": "Direct_IP_Host",
                "threat_category": "suspicious_structure",
                "severity": "MEDIUM",
                "description": "URL uses a direct IP address instead of a domain name."
            })

        if indicators["is_punycode_homograph"]:
            threats.append({
                "scanner_name": "url_analyzer",
                "threat_name": "Punycode_Homograph_Indicator",
                "threat_category": "phishing",
                "severity": "HIGH",
                "description": "Domain contains punycode (xn--), potential IDN homograph phishing."
            })

        if indicators["is_url_shortener"]:
            threats.append({
                "scanner_name": "url_analyzer",
                "threat_name": "URL_Shortener_Obfuscation",
                "threat_category": "heuristic",
                "severity": "LOW",
                "description": "URL uses a known shortening service that conceals destination."
            })

        # 2. Fetch URL content hop-by-hop with strict SSRF re-check on each redirect
        response_body = b""
        response_headers = {}
        status_code = 0
        final_url = current_url
        redirect_count = 0

        client = httpx.Client(
            follow_redirects=False,
            timeout=self.timeout,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) FileScanner/1.0 SecurityBot"}
        )

        try:
            while redirect_count <= self.max_redirects:
                # SSRF validation before making any HTTP request
                hop_safe, hop_error, _ = validate_url_security(current_url)
                if not hop_safe:
                    threats.append({
                        "scanner_name": "url_analyzer",
                        "threat_name": "SSRF_Redirect_Blocked",
                        "threat_category": "ssrf_violation",
                        "severity": "CRITICAL",
                        "description": f"Redirect destination blocked by SSRF protection: {hop_error}"
                    })
                    return self._build_result(
                        "MALICIOUS", target_url, current_url, redirect_chain, indicators, threats,
                        scanner_error=f"Redirect blocked: {hop_error}"
                    )

                try:
                    resp = client.get(current_url)
                except httpx.ConnectTimeout:
                    return self._build_result(
                        "UNABLE_TO_SCAN", target_url, current_url, redirect_chain, indicators, threats,
                        scanner_error=f"Connection timed out after {self.timeout}s"
                    )
                except Exception as e:
                    return self._build_result(
                        "UNABLE_TO_SCAN", target_url, current_url, redirect_chain, indicators, threats,
                        scanner_error=f"Failed to connect: {str(e)}"
                    )

                status_code = resp.status_code
                response_headers = dict(resp.headers)
                final_url = current_url

                # Check for HTTP redirect status codes
                if resp.is_redirect and "location" in resp.headers:
                    redirect_count += 1
                    location = resp.headers["location"]
                    next_url = urljoin(current_url, location)
                    redirect_chain.append(next_url)
                    current_url = next_url
                    continue
                else:
                    # Content stream with size limit
                    content = resp.content
                    if len(content) > self.max_size:
                        content = content[:self.max_size]
                        indicators["content_truncated"] = True
                    response_body = content
                    break

            if redirect_count > self.max_redirects:
                threats.append({
                    "scanner_name": "url_analyzer",
                    "threat_name": "Excessive_Redirect_Chain",
                    "threat_category": "heuristic",
                    "severity": "MEDIUM",
                    "description": f"Redirect chain exceeded {self.max_redirects} hops."
                })

        finally:
            client.close()

        # 3. Analyze Content and HTML
        indicators["http_status_code"] = status_code
        indicators["redirect_count"] = redirect_count
        indicators["https_supported"] = final_url.lower().startswith("https")

        if not indicators["https_supported"]:
            threats.append({
                "scanner_name": "url_analyzer",
                "threat_name": "Insecure_HTTP",
                "threat_category": "transport_security",
                "severity": "LOW",
                "description": "Target does not enforce HTTPS encryption."
            })

        # Parse HTML
        content_type = response_headers.get("content-type", "").lower()
        if "text/html" in content_type or b"<html" in response_body[:1024].lower():
            self._analyze_html_content(response_body, final_url, indicators, threats)

        # 4. YARA scan on fetched content
        yara_res = yara_service.scan_data(response_body)
        if yara_res.get("threats"):
            for t in yara_res["threats"]:
                threats.append(t)

        # 5. Determine Overall Status
        has_critical = any(t["severity"] in ("CRITICAL", "HIGH") for t in threats)
        has_medium = any(t["severity"] == "MEDIUM" for t in threats)

        if has_critical:
            overall_status = "MALICIOUS"
        elif has_medium or yara_res.get("status") == "SUSPICIOUS":
            overall_status = "SUSPICIOUS"
        else:
            overall_status = "CLEAN"

        scanner_results = {
            "url_analyzer": {
                "status": overall_status,
                "threats": [t for t in threats if t.get("scanner_name") == "url_analyzer"]
            },
            "yara": {
                "status": yara_res.get("status", "CLEAN"),
                "matched_rules": yara_res.get("matched_rules", []),
                "threats": yara_res.get("threats", [])
            }
        }

        return {
            "status": overall_status,
            "url": target_url,
            "final_url": final_url,
            "https_supported": indicators["https_supported"],
            "redirect_count": redirect_count,
            "redirect_chain": redirect_chain,
            "security_indicators": indicators,
            "scanner_results": scanner_results,
            "threats": threats
        }

    def _analyze_html_content(
        self,
        html_bytes: bytes,
        base_url: str,
        indicators: Dict[str, Any],
        threats: List[Dict[str, Any]]
    ):
        """Inspects HTML tree for phishing, hidden elements, and suspicious scripts."""
        try:
            soup = BeautifulSoup(html_bytes, "html.parser")
        except Exception:
            return

        # Title and Meta tags
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        indicators["page_title"] = title[:100]

        # Password inputs without HTTPS
        password_inputs = soup.find_all("input", attrs={"type": re.compile(r"^password$", re.I)})
        if password_inputs:
            indicators["contains_password_input"] = True
            if not base_url.lower().startswith("https"):
                threats.append({
                    "scanner_name": "url_analyzer",
                    "threat_name": "Insecure_Credential_Harvesting",
                    "threat_category": "phishing",
                    "severity": "CRITICAL",
                    "description": "Password field present on an unencrypted HTTP page."
                })

        # Form action checks
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action", "")
            if action:
                parsed_action = urlparse(action)
                parsed_base = urlparse(base_url)
                if parsed_action.netloc and parsed_action.netloc != parsed_base.netloc:
                    indicators["cross_domain_form_post"] = True
                    if password_inputs:
                        threats.append({
                            "scanner_name": "url_analyzer",
                            "threat_name": "Cross_Domain_Password_Submission",
                            "threat_category": "phishing",
                            "severity": "HIGH",
                            "description": f"Form with credentials submits to external domain: {parsed_action.netloc}"
                        })

        # Hidden IFrames (common drive-by download / clickjacking indicator)
        iframes = soup.find_all("iframe")
        for iframe in iframes:
            style = iframe.get("style", "").lower()
            width = iframe.get("width", "")
            height = iframe.get("height", "")
            if "display:none" in style or "visibility:hidden" in style or width in ("0", "1") or height in ("0", "1"):
                indicators["hidden_iframe_detected"] = True
                threats.append({
                    "scanner_name": "url_analyzer",
                    "threat_name": "Hidden_IFrame",
                    "threat_category": "suspicious_html",
                    "severity": "MEDIUM",
                    "description": "Hidden or zero-sized iframe detected on page."
                })

        # Malicious download links
        links = soup.find_all("a", href=True)
        for link in links:
            href = link["href"].lower()
            for ext in MALICIOUS_DOWNLOAD_EXTENSIONS:
                if href.endswith(ext) or f"{ext}?" in href:
                    indicators["direct_executable_download_link"] = href
                    threats.append({
                        "scanner_name": "url_analyzer",
                        "threat_name": "Malicious_Download_Link",
                        "threat_category": "suspicious_download",
                        "severity": "MEDIUM",
                        "description": f"Page contains link to direct executable/script download: {ext}"
                    })
                    break

    def _build_result(
        self,
        status: str,
        target_url: str,
        final_url: Optional[str],
        redirect_chain: List[str],
        indicators: Dict[str, Any],
        threats: List[Dict[str, Any]],
        scanner_error: Optional[str] = None
    ) -> Dict[str, Any]:
        return {
            "status": status,
            "url": target_url,
            "final_url": final_url,
            "https_supported": target_url.lower().startswith("https"),
            "redirect_count": len(redirect_chain) - 1,
            "redirect_chain": redirect_chain,
            "security_indicators": indicators,
            "scanner_results": {
                "url_analyzer": {
                    "status": status,
                    "threats": threats,
                    "error": scanner_error
                }
            },
            "threats": threats
        }


url_service = URLService()

