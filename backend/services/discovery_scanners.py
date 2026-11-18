"""Discovery and utility scanners.

Implements the scan types that were previously only mapped to generic
Nmap/Nuclei runs, plus the remaining Pentest-Tools style tools:

* SubdomainScanner      - subfinder based subdomain enumeration
* ReconScanner          - whatweb + HTTP header/technology fingerprinting
* PasswordAuditorScanner- anonymous/default credential exposure checks
* GoogleHackingScanner  - search-engine dorking for exposed data
* PeopleHunterScanner   - OSINT email/people harvesting (theHarvester)
* DomainFinderScanner   - certificate transparency related domains
* VHostScanner          - virtual host discovery (gobuster vhost)
* URLFuzzerScanner      - content discovery / directory fuzzing (ffuf)
* HTTPRequestLoggerScanner - capture HTTP request/response log

All scanners degrade gracefully when an external tool or the network is
unavailable: they still complete and record what was (not) observed.
"""
from __future__ import annotations

import asyncio
import base64
import html
import json
import os
import re
import shutil
import tempfile
import time
from datetime import datetime
from typing import Any, Dict, List
from urllib.parse import urlparse, unquote

import httpx

from services.scanner_base import BaseScanner, ScanFinding, ScanResult

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"

VHOST_WORDS = [
    "www", "dev", "staging", "stage", "test", "testing", "qa", "uat", "admin",
    "administrator", "api", "api-dev", "api-staging", "app", "apps", "mail",
    "webmail", "smtp", "mx", "portal", "intranet", "internal", "vpn", "git",
    "gitlab", "jenkins", "ci", "cd", "build", "beta", "demo", "sandbox",
    "m", "mobile", "shop", "store", "blog", "wiki", "docs", "support",
    "status", "monitor", "grafana", "kibana", "prometheus", "db", "sql",
    "backup", "old", "new", "legacy", "static", "assets", "cdn", "files",
]

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]


def _domain_from_target(target: str) -> str:
    raw = (target or "").strip()
    if "://" not in raw:
        raw = "http://" + raw
    host = urlparse(raw).hostname or target
    return host.strip(".").lower()


def _base_url(target: str) -> str:
    raw = (target or "").strip()
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def _bounded_timeout(options: Dict[str, Any], default: int, cap: int) -> int:
    try:
        value = int(options.get("timeout") or default)
    except (TypeError, ValueError):
        value = default
    return max(10, min(value, cap))


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or ""))


def _looks_sensitive(path: str) -> bool:
    return bool(re.search(
        r"(\.git|\.svn|\.env|\.htpasswd|\.htaccess|backup|\.bak|\.old|\.swp|~$|"
        r"config|conf/|db\.|dump|\.sql(?:$|\?)|phpinfo|server-status|"
        r"admin|manager|console|debug|actuator|swagger|\.ds_store)",
        path or "", re.I,
    ))


class SubdomainScanner(BaseScanner):
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "SubdomainScanner"

    def validate_target(self, target: str) -> bool:
        return bool(_domain_from_target(target))

    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        started = datetime.utcnow()
        domain = _domain_from_target(target)
        findings: List[ScanFinding] = []
        raw = ""
        notes: List[str] = []

        if shutil.which("subfinder"):
            out, err, code = await self.run_command(
                ["subfinder", "-d", domain, "-silent", "-timeout", "10"],
                timeout=_bounded_timeout(options, 240, 300),
            )
            raw = out
            if code != 0:
                notes.append(f"subfinder exit {code}: {err[:300]}")
        else:
            notes.append("subfinder not installed")

        subdomains = sorted({
            line.strip().lower() for line in raw.splitlines()
            if line.strip() and "." in line and re.fullmatch(r"[a-z0-9*_.-]+", line.strip().lower())
        })
        notes.append(f"subfinder reported {len(subdomains)} candidates")

        # Resolve candidates with dnsx to drop wildcard/CT noise when possible.
        raw_count = len(subdomains)
        verified = False
        if subdomains and shutil.which("dnsx"):
            candidates = subdomains[:4000]
            fd, path = tempfile.mkstemp(prefix="subs_", text=True)
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write("\n".join(candidates) + "\n")
                out, err, code = await self.run_command(
                    ["dnsx", "-silent", "-l", path, "-a", "-t", "100", "-retry", "1"],
                    timeout=_bounded_timeout(options, 120, 180),
                )
                resolved = sorted({
                    line.split()[0].strip().lower() for line in out.splitlines()
                    if line.strip() and re.fullmatch(r"[a-z0-9*_.-]+", line.split()[0].strip().lower())
                })
                if resolved:
                    subdomains = resolved
                    verified = True
                    notes.append(f"dnsx resolved {len(resolved)} of {len(candidates)} candidates")
                elif code != 0:
                    notes.append(f"dnsx exit {code}: {err[:200]}")
                else:
                    notes.append(f"dnsx resolved none of {len(candidates)} candidates")
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass

        if not verified:
            if len(subdomains) > 500:
                notes.append(f"{len(subdomains)} unverified candidates truncated to 500")
                subdomains = subdomains[:500]
            notes.append("results are unverified (DNS resolution unavailable or no matches)")

        if not subdomains:
            # DNS fallback: resolve a small builtin candidate list
            candidates = [f"{w}.{domain}" for w in ("www", "mail", "api", "dev", "staging", "admin", "test", "vpn", "portal", "git")]
            loop = asyncio.get_running_loop()

            async def resolve(host: str):
                try:
                    await loop.getaddrinfo(host, None)
                    return host
                except Exception:
                    return None

            resolved = await asyncio.gather(*(resolve(c) for c in candidates))
            subdomains = sorted({r for r in resolved if r})
            if subdomains:
                notes.append("subfinder produced nothing; used DNS candidate fallback")

        if subdomains:
            findings.append(ScanFinding(
                title=f"Subdomains discovered ({len(subdomains)})",
                description=(
                    f"Discovered {len(subdomains)} subdomain(s) for {domain}"
                    + (" (DNS-verified)" if verified else f" out of {raw_count} unverified candidates")
                    + ": " + ", ".join(subdomains[:30])
                ),
                severity="info",
                target_url=f"https://{domain}",
                evidence={
                    "domain": domain,
                    "subdomains": subdomains[:500],
                    "count": len(subdomains),
                    "raw_candidate_count": raw_count,
                    "dns_verified": verified,
                    "notes": notes,
                },
                source_scanner=self.name,
                source_finding_id=f"subdomains_{domain}",
                tags=["discovery", "subdomain"],
            ))
        else:
            findings.append(ScanFinding(
                title="No subdomains discovered",
                description=f"No subdomains were found for {domain}.",
                severity="info",
                target_url=f"https://{domain}",
                evidence={"domain": domain, "notes": notes},
                source_scanner=self.name,
                tags=["discovery", "subdomain"],
            ))

        completed = datetime.utcnow()
        return ScanResult(
            scan_id=options.get("scan_id", "unknown"),
            scanner_name=self.name,
            status="completed",
            findings=findings,
            raw_output="\n".join(subdomains)[:100000],
            started_at=started,
            completed_at=completed,
            duration_seconds=int((completed - started).total_seconds()),
            metadata={"domain": domain, "notes": notes},
        )


class ReconScanner(BaseScanner):
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "ReconScanner"

    def validate_target(self, target: str) -> bool:
        return bool(_base_url(target))

    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        started = datetime.utcnow()
        url = _base_url(target)
        findings: List[ScanFinding] = []
        fingerprint: Dict[str, Any] = {"url": url}
        notes: List[str] = []

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20, headers={"User-Agent": UA}) as client:
            try:
                resp = await client.get(target if "://" in target else url)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                fingerprint.update({
                    "final_url": str(resp.url),
                    "status_code": resp.status_code,
                    "server": headers.get("server", ""),
                    "powered_by": headers.get("x-powered-by", ""),
                    "content_type": headers.get("content-type", ""),
                    "cookies": [c.split("=")[0].strip() for c in resp.headers.get_list("set-cookie")],
                    "security_headers": {h: headers.get(h, "") for h in SECURITY_HEADERS},
                })
                title = re.search(r"<title[^>]*>(.*?)</title>", resp.text[:200000], re.I | re.S)
                generator = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', resp.text[:200000], re.I)
                fingerprint["title"] = html.unescape(title.group(1)).strip()[:200] if title else ""
                fingerprint["generator"] = generator.group(1) if generator else ""
                fingerprint["tech_hints"] = sorted(set(re.findall(
                    r"(wordpress|drupal|joomla|react|angular|vue|next\.js|nuxt|jquery|bootstrap|"
                    r"laravel|django|flask|rails|spring|asp\.net|php|nginx|apache|iis|cloudflare|"
                    r"shopify|magento|woocommerce|grafana|jenkins)",
                    (resp.text[:200000] + " " + json.dumps(headers)).lower(),
                )))
                missing = [h for h in SECURITY_HEADERS if not headers.get(h)]
                fingerprint["missing_security_headers"] = missing
            except Exception as exc:
                notes.append(f"HTTP request failed: {exc}")
                missing = []

        if shutil.which("whatweb"):
            fd, path = tempfile.mkstemp(suffix=".json", prefix="whatweb_")
            os.close(fd)
            try:
                out, err, code = await self.run_command(
                    ["whatweb", "-a", "1", "--no-errors", f"--log-json={path}", f"--user-agent={UA}", url],
                    timeout=_bounded_timeout(options, 120, 180),
                )
                plugins: Dict[str, Any] = {}
                if os.path.exists(path):
                    with open(path, "r", errors="ignore") as fh:
                        for line in fh:
                            try:
                                rec = json.loads(line)
                            except json.JSONDecodeError:
                                continue
                            plugins.update(rec.get("plugins", {}))
                fingerprint["whatweb_plugins"] = sorted(plugins.keys())
                if code != 0 and err and not plugins:
                    notes.append(f"whatweb exit {code}: {err[:200]}")
            finally:
                try:
                    os.unlink(path)
                except OSError:
                    pass

        tech = ", ".join(filter(None, [
            fingerprint.get("server"),
            fingerprint.get("powered_by"),
            ", ".join(fingerprint.get("tech_hints") or []),
            ", ".join(fingerprint.get("whatweb_plugins") or []),
        ]))
        findings.append(ScanFinding(
            title="Technology fingerprint",
            description=f"Detected technologies for {url}: {tech or 'no clear fingerprint'}",
            severity="info",
            target_url=url,
            evidence=fingerprint,
            source_scanner=self.name,
            source_finding_id=f"recon_{url}",
            tags=["recon", "fingerprint"],
        ))

        if fingerprint.get("missing_security_headers"):
            findings.append(ScanFinding(
                title="Missing HTTP security headers",
                description="The following security headers are missing: " + ", ".join(fingerprint["missing_security_headers"]),
                severity="low",
                target_url=url,
                remediation="Add the missing headers at the web server or application layer.",
                evidence={"missing": fingerprint["missing_security_headers"]},
                source_scanner=self.name,
                source_finding_id=f"headers_{url}",
                tags=["recon", "headers", "hardening"],
            ))

        completed = datetime.utcnow()
        return ScanResult(
            scan_id=options.get("scan_id", "unknown"),
            scanner_name=self.name,
            status="completed",
            findings=findings,
            raw_output=json.dumps(fingerprint, indent=2, default=str)[:100000],
            started_at=started,
            completed_at=completed,
            duration_seconds=int((completed - started).total_seconds()),
            metadata={"url": url, "notes": notes},
        )


class PasswordAuditorScanner(BaseScanner):
    """Checks for anonymous / default credential exposures.

    Aggressive credential brute forcing only runs when the caller explicitly
    supplies a service, username list and password list in scanner_config.
    """

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "PasswordAuditorScanner"

    def validate_target(self, target: str) -> bool:
        return bool(target)

    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        started = datetime.utcnow()
        host = _domain_from_target(target)
        findings: List[ScanFinding] = []
        notes: List[str] = []
        raw = ""

        if shutil.which("nmap"):
            out, err, code = await self.run_command([
                "nmap", "-Pn", "-sV", "--script", "ftp-anon,http-default-accounts,ssh-auth-methods",
                "--script-timeout", "45s", "-p", "21,22,80,443,8080,8443", host,
            ], timeout=_bounded_timeout(options, 300, 420))
            raw += out
            if code != 0:
                notes.append(f"nmap exit {code}: {err[:300]}")
            if re.search(r"Anonymous FTP login allowed", out, re.I):
                findings.append(ScanFinding(
                    title="Anonymous FTP login allowed",
                    description="The FTP service accepts anonymous logins, exposing files to unauthenticated users.",
                    severity="high",
                    target_url=f"ftp://{host}",
                    evidence={"scanner": "nmap ftp-anon"},
                    remediation="Disable anonymous FTP access.",
                    source_scanner=self.name,
                    source_finding_id=f"ftp_anon_{host}",
                    tags=["password", "ftp", "anonymous"],
                ))
            if re.search(r"http-default-accounts.*(?:Valid credentials|default credentials)|login:\s*\S+", out, re.I | re.S):
                findings.append(ScanFinding(
                    title="Default HTTP credentials discovered",
                    description="nmap http-default-accounts discovered valid default credentials for the web server.",
                    severity="high",
                    target_url=_base_url(target),
                    evidence={"output": out[-4000:]},
                    remediation="Enforce strong credentials and rate limiting.",
                    source_scanner=self.name,
                    source_finding_id=f"httpbasic_{host}",
                    tags=["password", "http", "default-credentials"],
                ))
            if re.search(r"ssh-auth-methods.*password", out, re.I | re.S):
                findings.append(ScanFinding(
                    title="SSH password authentication enabled",
                    description="The SSH service allows password authentication, which is susceptible to brute force.",
                    severity="low",
                    target_url=f"ssh://{host}",
                    evidence={"scanner": "nmap ssh-auth-methods"},
                    remediation="Prefer key-based authentication and fail2ban.",
                    source_scanner=self.name,
                    source_finding_id=f"ssh_password_{host}",
                    tags=["password", "ssh"],
                ))
        else:
            notes.append("nmap not installed")

        service = options.get("service")
        usernames = options.get("usernames") or []
        passwords = options.get("passwords") or []
        if service and usernames and passwords and shutil.which("hydra"):
            ufd, upath = tempfile.mkstemp(prefix="users_")
            pfd, ppath = tempfile.mkstemp(prefix="pass_")
            try:
                with os.fdopen(ufd, "w") as fh:
                    fh.write("\n".join(usernames) + "\n")
                with os.fdopen(pfd, "w") as fh:
                    fh.write("\n".join(passwords) + "\n")
                out, err, code = await self.run_command([
                    "hydra", "-L", upath, "-P", ppath, "-t", "2", "-f",
                    "-s", str(options.get("port", 22)), service, host,
                ], timeout=_bounded_timeout(options, 300, 420))
                raw += "\n" + out
                for match in re.findall(r"login:\s+(\S+)\s+password:\s+(\S+)", out):
                    findings.append(ScanFinding(
                        title=f"Valid credentials found ({service})",
                        description=f"Credential brute force found working login for {service}.",
                        severity="critical",
                        target_url=f"{service}://{host}",
                        evidence={"username": match[0], "password": match[1], "service": service},
                        remediation="Rotate the credential, enforce lockout and MFA.",
                        source_scanner=self.name,
                        source_finding_id=f"hydra_{service}_{host}_{match[0]}",
                        tags=["password", "bruteforce", "credentials"],
                    ))
            finally:
                for path in (upath, ppath):
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
        elif service:
            notes.append("hydra brute force skipped (missing service/usernames/passwords or hydra)")

        if not findings:
            findings.append(ScanFinding(
                title="No weak credentials identified",
                description="No anonymous or default credential exposure was identified by the enabled checks.",
                severity="info",
                target_url=_base_url(target),
                evidence={"notes": notes},
                source_scanner=self.name,
                source_finding_id=f"password_none_{host}",
                tags=["password"],
            ))

        completed = datetime.utcnow()
        return ScanResult(
            scan_id=options.get("scan_id", "unknown"),
            scanner_name=self.name,
            status="completed",
            findings=findings,
            raw_output=raw[:100000],
            started_at=started,
            completed_at=completed,
            duration_seconds=int((completed - started).total_seconds()),
            metadata={"host": host, "notes": notes},
        )


class GoogleHackingScanner(BaseScanner):
    DORKS = [
        'site:{d} ext:sql OR ext:env OR ext:log OR ext:bak',
        'site:{d} intitle:"index of"',
        'site:{d} ext:pdf OR ext:xls OR ext:doc',
        'site:{d} inurl:admin OR inurl:login',
        'site:pastebin.com "{d}"',
        '"{d}" password OR api_key OR token',
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "GoogleHackingScanner"
        self._engine_notes: List[str] = []

    def validate_target(self, target: str) -> bool:
        return bool(_domain_from_target(target))

    async def _search(self, dork: str) -> List[Dict[str, str]]:
        results: List[Dict[str, str]] = []
        self._engine_notes = []
        headers = {"User-Agent": UA}
        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20, headers=headers) as client:
            try:
                resp = await client.get("https://html.duckduckgo.com/html/", params={"q": dork})
                if resp.status_code != 200:
                    self._engine_notes.append(f"duckduckgo status {resp.status_code}")
                elif "anomaly" in resp.text.lower():
                    self._engine_notes.append("duckduckgo challenge page")
                if resp.status_code == 200 and "anomaly" not in resp.text.lower():
                    for block in re.findall(r'<a[^>]+class="result__a"[^>]+href="([^"]+)"[^>]*>(.*?)</a>', resp.text, re.I | re.S)[:10]:
                        href, label = block
                        if "uddg=" in href:
                            href = unquote(re.search(r"uddg=([^&]+)", href).group(1))
                        results.append({"url": href, "title": re.sub("<[^>]+>", "", html.unescape(label)).strip()})
            except Exception as exc:
                self._engine_notes.append(f"duckduckgo error: {exc}"[:160])
            if not results:
                try:
                    resp = await client.get("https://www.bing.com/search", params={"q": dork, "count": "20"})
                    if resp.status_code == 200:
                        for href, label in re.findall(r'<h2><a[^>]+href="(http[^"]+)"[^>]*>(.*?)</a>', resp.text, re.I | re.S)[:10]:
                            href = html.unescape(href)
                            encoded = re.search(r"[?&]u=a1([^&]+)", href)
                            if encoded:
                                token = encoded.group(1) + "=" * (-len(encoded.group(1)) % 4)
                                try:
                                    href = base64.urlsafe_b64decode(token).decode("utf-8", "ignore")
                                except Exception:
                                    pass
                            results.append({"url": href, "title": re.sub("<[^>]+>", "", html.unescape(label)).strip()})
                except Exception as exc:
                    self._engine_notes.append(f"bing error: {exc}"[:160])
        if not results and not self._engine_notes:
            self._engine_notes.append("search engines returned no parsable results")
        return results

    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        started = datetime.utcnow()
        domain = _domain_from_target(target)
        findings: List[ScanFinding] = []
        raw: Dict[str, Any] = {}
        hit_total = 0

        for template in self.DORKS:
            dork = template.format(d=domain)
            hits = await self._search(dork)
            hits = [
                h for h in hits
                if domain in ((h.get("url") or "") + " " + (h.get("title") or "")).lower()
            ]
            raw[dork] = hits
            hit_total += len(hits)
            if hits:
                sensitive = any(re.search(r"\.(sql|env|log|bak)(\?|$)", h["url"], re.I) for h in hits)
                findings.append(ScanFinding(
                    title=f"Google dork matches: {dork}",
                    description=f"Dork '{dork}' returned {len(hits)} result(s).",
                    severity="medium" if sensitive else "low",
                    target_url=f"https://www.google.com/search?q={dork}",
                    evidence={"dork": dork, "results": hits[:10]},
                    remediation="Review exposed documents/data and remove or restrict access.",
                    source_scanner=self.name,
                    source_finding_id=f"dork_{abs(hash(dork))}",
                    tags=["osint", "google-hacking", "dork"],
                ))

        if hit_total == 0:
            findings.append(ScanFinding(
                title="No Google dork results",
                description=f"No search-engine results were found for the dorks against {domain} (search engines may have rate limited the request).",
                severity="info",
                target_url=f"https://{domain}",
                evidence={"dorks": list(raw.keys()), "engine_notes": self._engine_notes[-10:]},
                source_scanner=self.name,
                source_finding_id=f"dork_none_{domain}",
                tags=["osint", "google-hacking"],
            ))

        completed = datetime.utcnow()
        return ScanResult(
            scan_id=options.get("scan_id", "unknown"),
            scanner_name=self.name,
            status="completed",
            findings=findings,
            raw_output=json.dumps(raw, indent=2, default=str)[:100000],
            started_at=started,
            completed_at=completed,
            duration_seconds=int((completed - started).total_seconds()),
            metadata={"domain": domain, "dork_hits": hit_total, "engine_notes": self._engine_notes[-10:]},
        )


class PeopleHunterScanner(BaseScanner):
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "PeopleHunterScanner"

    def validate_target(self, target: str) -> bool:
        return bool(_domain_from_target(target))

    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        started = datetime.utcnow()
        domain = _domain_from_target(target)
        findings: List[ScanFinding] = []
        emails: List[str] = []
        hosts: List[str] = []
        notes: List[str] = []
        raw = ""

        tool = shutil.which("theHarvester") or shutil.which("theharvester")
        if tool:
            base = os.path.join(tempfile.gettempdir(), f"harv_{int(time.time())}")
            out, err, code = await self.run_command([
                tool, "-d", domain, "-b", "duckduckgo,bing", "-l", "200", "-f", base,
            ], timeout=_bounded_timeout(options, 240, 300))
            raw = out
            for suffix in (".json", ".xml", ""):
                path = base + suffix
                if os.path.exists(path):
                    try:
                        with open(path, "r", errors="ignore") as fh:
                            data = json.load(fh)
                        emails.extend(data.get("emails") or [])
                        hosts.extend(data.get("hosts") or [])
                    except Exception:
                        pass
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
            if code != 0:
                notes.append(f"theHarvester exit {code}: {err[:200]}")
        else:
            notes.append("theHarvester not installed")

        emails.extend(re.findall(r"[A-Za-z0-9._%+-]+@" + re.escape(domain), raw))
        emails = sorted({e.lower() for e in emails if "@" in e})
        hosts = sorted({h.lower() for h in hosts if h})

        if not emails:
            # DDG fallback for public mentions
            try:
                async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20, headers={"User-Agent": UA}) as client:
                    resp = await client.get("https://html.duckduckgo.com/html/", params={"q": f'"@{domain}"'})
                    emails = sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@" + re.escape(domain), html.unescape(resp.text))))
            except Exception as exc:
                notes.append(f"fallback search failed: {exc}")

        if emails:
            findings.append(ScanFinding(
                title=f"Email addresses discovered ({len(emails)})",
                description="Publicly discoverable email addresses: " + ", ".join(emails[:30]),
                severity="medium",
                target_url=f"https://{domain}",
                evidence={"emails": emails[:500], "hosts": hosts[:200]},
                remediation="Reduce public exposure of employee addresses and enforce phishing-resistant MFA.",
                source_scanner=self.name,
                source_finding_id=f"people_{domain}",
                tags=["osint", "people", "email"],
            ))
        else:
            findings.append(ScanFinding(
                title="No people/email data discovered",
                description=f"No public email addresses were discovered for {domain}.",
                severity="info",
                target_url=f"https://{domain}",
                evidence={"notes": notes},
                source_scanner=self.name,
                source_finding_id=f"people_none_{domain}",
                tags=["osint", "people"],
            ))

        if hosts:
            findings.append(ScanFinding(
                title=f"Hosts discovered via OSINT ({len(hosts)})",
                description="Hosts found by OSINT sources: " + ", ".join(hosts[:30]),
                severity="info",
                target_url=f"https://{domain}",
                evidence={"hosts": hosts[:500]},
                source_scanner=self.name,
                source_finding_id=f"people_hosts_{domain}",
                tags=["osint", "hosts"],
            ))

        completed = datetime.utcnow()
        return ScanResult(
            scan_id=options.get("scan_id", "unknown"),
            scanner_name=self.name,
            status="completed",
            findings=findings,
            raw_output=(raw or json.dumps({"emails": emails, "hosts": hosts}))[:100000],
            started_at=started,
            completed_at=completed,
            duration_seconds=int((completed - started).total_seconds()),
            metadata={"domain": domain, "emails_count": len(emails), "hosts_count": len(hosts), "notes": notes},
        )


class DomainFinderScanner(BaseScanner):
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "DomainFinderScanner"

    def validate_target(self, target: str) -> bool:
        return bool(_domain_from_target(target))

    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        started = datetime.utcnow()
        domain = _domain_from_target(target)
        findings: List[ScanFinding] = []
        notes: List[str] = []
        names: set[str] = set()
        raw = ""

        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=40, headers={"User-Agent": UA}) as client:
                resp = await client.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"})
                raw = resp.text
                if resp.status_code == 200:
                    for row in resp.json():
                        for value in (row.get("name_value") or "").splitlines():
                            value = value.strip().lower().lstrip("*.")
                            if value and "." in value:
                                names.add(value)
                else:
                    notes.append(f"crt.sh returned HTTP {resp.status_code}")
        except Exception as exc:
            notes.append(f"crt.sh query failed: {exc}")

        # Related registrable names (last two labels) and parent domains
        related = sorted({".".join(n.split(".")[-2:]) for n in names if n.endswith(domain)} - {domain})
        subdomains = sorted(n for n in names if n.endswith(domain))
        external = sorted({".".join(n.split(".")[-2:]) for n in names} - {domain})

        if shutil.which("dig"):
            for record in ("NS", "MX"):
                out, _, _ = await self.run_command(["dig", "+short", record, domain], timeout=30)
                if out.strip():
                    findings.append(ScanFinding(
                        title=f"{record} records for {domain}",
                        description=f"{record} records: {out.strip().replace(chr(10), ', ')}",
                        severity="info",
                        target_url=f"https://{domain}",
                        evidence={"record": record, "values": out.split()},
                        source_scanner=self.name,
                        source_finding_id=f"dns_{record}_{domain}",
                        tags=["osint", "dns", "domain"],
                    ))

        all_domains = sorted(set(subdomains) | set(related))
        if all_domains:
            findings.append(ScanFinding(
                title=f"Related domains/subdomains discovered ({len(all_domains)})",
                description="Certificate transparency records revealed: " + ", ".join(all_domains[:40]),
                severity="info",
                target_url=f"https://{domain}",
                evidence={
                    "subdomains": subdomains[:500],
                    "related_domains": related[:100],
                    "external_hosts": external[:100],
                },
                source_scanner=self.name,
                source_finding_id=f"domains_{domain}",
                tags=["osint", "domain", "certificate-transparency"],
            ))
        else:
            findings.append(ScanFinding(
                title="No related domains discovered",
                description=f"Certificate transparency returned no related names for {domain}.",
                severity="info",
                target_url=f"https://{domain}",
                evidence={"notes": notes},
                source_scanner=self.name,
                source_finding_id=f"domains_none_{domain}",
                tags=["osint", "domain"],
            ))

        completed = datetime.utcnow()
        return ScanResult(
            scan_id=options.get("scan_id", "unknown"),
            scanner_name=self.name,
            status="completed",
            findings=findings,
            raw_output=raw[:100000],
            started_at=started,
            completed_at=completed,
            duration_seconds=int((completed - started).total_seconds()),
            metadata={"domain": domain, "names": len(all_domains), "notes": notes},
        )


class VHostScanner(BaseScanner):
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "VHostScanner"

    def validate_target(self, target: str) -> bool:
        return bool(_base_url(target))

    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        started = datetime.utcnow()
        url = _base_url(target)
        host = _domain_from_target(target)
        findings: List[ScanFinding] = []
        notes: List[str] = []
        raw = ""
        found: List[Dict[str, Any]] = []

        # Baseline response size for a non-existent host to filter wildcard vhosts
        baseline = None
        try:
            async with httpx.AsyncClient(verify=False, follow_redirects=False, timeout=15, headers={"User-Agent": UA}) as client:
                baseline_resp = await client.get(url, headers={"Host": f"nope-{int(time.time())}.{host}"})
                baseline = len(baseline_resp.content)
        except Exception:
            pass

        if shutil.which("gobuster"):
            fd, wpath = tempfile.mkstemp(prefix="vhosts_", text=True)
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write("\n".join(VHOST_WORDS) + "\n")
                cmd = [
                    "gobuster", "vhost", "-u", url, "-w", wpath,
                    "--append-domain", "-k", "-t", "20", "--timeout", "10s", "--no-progress",
                ]
                if baseline is not None:
                    cmd.extend(["--exclude-length", str(baseline)])
                out, err, code = await self.run_command(cmd, timeout=_bounded_timeout(options, 300, 420))
                raw = out
                if code != 0:
                    notes.append(f"gobuster exit {code}: {err[:300]}")
                for line in out.splitlines():
                    if "Status:" in line or "Found:" in line:
                        hostname = line.split()[0] if line.split() else ""
                        status = re.search(r"Status:\s*(\d+)", line)
                        size = re.search(r"Size:\s*(\d+)", line)
                        if hostname:
                            found.append({"host": hostname, "status": status.group(1) if status else "", "size": size.group(1) if size else ""})
            finally:
                try:
                    os.unlink(wpath)
                except OSError:
                    pass
        else:
            notes.append("gobuster not installed")

        for item in found:
            findings.append(ScanFinding(
                title=f"Virtual host discovered: {item['host']}",
                description=f"Virtual host {item['host']} responded with HTTP {item['status']}.",
                severity="low",
                target_url=url,
                evidence=item,
                remediation="Restrict unintended virtual hosts and default vhost behaviour.",
                source_scanner=self.name,
                source_finding_id=f"vhost_{item['host']}",
                tags=["discovery", "vhost"],
            ))

        if not found:
            findings.append(ScanFinding(
                title="No additional virtual hosts discovered",
                description=f"No virtual hosts beyond the default were identified for {host}.",
                severity="info",
                target_url=url,
                evidence={"notes": notes, "baseline_length": baseline},
                source_scanner=self.name,
                source_finding_id=f"vhost_none_{host}",
                tags=["discovery", "vhost"],
            ))

        completed = datetime.utcnow()
        return ScanResult(
            scan_id=options.get("scan_id", "unknown"),
            scanner_name=self.name,
            status="completed",
            findings=findings,
            raw_output=raw[:100000],
            started_at=started,
            completed_at=completed,
            duration_seconds=int((completed - started).total_seconds()),
            metadata={"url": url, "found": len(found), "notes": notes},
        )


class URLFuzzerScanner(BaseScanner):
    WORDLISTS = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ]

    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "URLFuzzerScanner"

    def validate_target(self, target: str) -> bool:
        return bool(_base_url(target))

    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        started = datetime.utcnow()
        url = _base_url(target)
        findings: List[ScanFinding] = []
        notes: List[str] = []
        raw = ""
        results: List[Dict[str, Any]] = []

        wordlist = next((w for w in self.WORDLISTS if os.path.exists(w)), None)
        if not wordlist:
            notes.append("no wordlist found")
        elif shutil.which("ffuf"):
            fd, outpath = tempfile.mkstemp(suffix=".json", prefix="ffuf_")
            os.close(fd)
            try:
                out, err, code = await self.run_command([
                    "ffuf", "-u", f"{url}/FUZZ", "-w", wordlist,
                    "-mc", "200,204,301,302,307,401,403", "-t", "40", "-timeout", "10",
                    "-s", "-of", "json", "-o", outpath,
                ], timeout=_bounded_timeout(options, 300, 420))
                raw = out + err
                if code != 0:
                    notes.append(f"ffuf exit {code}: {err[:300]}")
                if os.path.exists(outpath):
                    with open(outpath, "r", errors="ignore") as fh:
                        data = json.load(fh)
                    results = data.get("results", []) or []
            except Exception as exc:
                notes.append(f"ffuf failed: {exc}")
            finally:
                try:
                    os.unlink(outpath)
                except OSError:
                    pass
        else:
            notes.append("ffuf not installed")

        interesting = []
        for row in results:
            path = urlparse(row.get("url", "")).path
            item = {
                "url": row.get("url"),
                "status": row.get("status"),
                "length": row.get("length"),
                "content_type": (row.get("content-type") or row.get("content_type") or ""),
            }
            interesting.append(item)
            if _looks_sensitive(path):
                findings.append(ScanFinding(
                    title=f"Sensitive path exposed: {path}",
                    description=f"{row.get('url')} returned HTTP {row.get('status')} during content discovery.",
                    severity="high" if re.search(r"(\.git|\.env|backup|dump|\.sql|config)", path, re.I) else "medium",
                    target_url=row.get("url", url),
                    path=path,
                    evidence=item,
                    remediation="Remove the resource from the web root or restrict access.",
                    source_scanner=self.name,
                    source_finding_id=f"fuzz_{abs(hash(row.get('url', '')))}",
                    tags=["discovery", "fuzzing", "exposure"],
                ))

        if interesting and not findings:
            findings.append(ScanFinding(
                title=f"Discoverable paths ({len(interesting)})",
                description="Content discovery found reachable paths: " + ", ".join(
                    urlparse(i["url"]).path for i in interesting[:25]
                ),
                severity="info",
                target_url=url,
                evidence={"results": interesting[:100], "wordlist": wordlist},
                source_scanner=self.name,
                source_finding_id=f"fuzz_paths_{url}",
                tags=["discovery", "fuzzing"],
            ))
        elif not interesting:
            findings.append(ScanFinding(
                title="No additional paths discovered",
                description=f"Content discovery found no extra paths for {url}.",
                severity="info",
                target_url=url,
                evidence={"notes": notes, "wordlist": wordlist},
                source_scanner=self.name,
                source_finding_id=f"fuzz_none_{url}",
                tags=["discovery", "fuzzing"],
            ))

        completed = datetime.utcnow()
        return ScanResult(
            scan_id=options.get("scan_id", "unknown"),
            scanner_name=self.name,
            status="completed",
            findings=findings,
            raw_output=raw[:100000],
            started_at=started,
            completed_at=completed,
            duration_seconds=int((completed - started).total_seconds()),
            metadata={"url": url, "results": len(results), "notes": notes},
        )


class HTTPRequestLoggerScanner(BaseScanner):
    def __init__(self, config: Dict[str, Any] = None):
        super().__init__(config)
        self.name = "HTTPRequestLoggerScanner"

    def validate_target(self, target: str) -> bool:
        return bool(_base_url(target))

    async def scan(self, target: str, options: Dict[str, Any]) -> ScanResult:
        started = datetime.utcnow()
        url = _base_url(target)
        entry_url = target if "://" in target else url
        log: List[Dict[str, Any]] = []
        findings: List[ScanFinding] = []
        notes: List[str] = []

        async with httpx.AsyncClient(verify=False, follow_redirects=True, timeout=20, headers={"User-Agent": UA}) as client:
            async def capture(method: str, req_url: str):
                t0 = time.time()
                try:
                    resp = await client.request(method, req_url)
                    log.append({
                        "method": method,
                        "url": str(resp.url),
                        "status": resp.status_code,
                        "request_headers": dict(resp.request.headers),
                        "response_headers": dict(resp.headers),
                        "content_length": len(resp.content),
                        "duration_ms": int((time.time() - t0) * 1000),
                    })
                    return resp
                except Exception as exc:
                    log.append({"method": method, "url": req_url, "error": str(exc)})
                    return None

            main = await capture("GET", entry_url)
            resources: List[str] = []
            if main is not None and "html" in (main.headers.get("content-type", "") or "").lower():
                body = main.text[:500000]
                for raw in re.findall(r'(?:src|href)=["\']([^"\']+)["\']', body, re.I):
                    if raw.startswith(("http://", "https://")):
                        resources.append(raw)
                    elif raw.startswith("/"):
                        resources.append(url + raw)
                resources = list(dict.fromkeys(resources))[:25]
                for res_url in resources:
                    await capture("HEAD", res_url)

        if main is not None:
            headers = {k.lower(): v for k, v in main.headers.items()}
            cookie_issues = []
            for cookie in main.headers.get_list("set-cookie"):
                if "httponly" not in cookie.lower():
                    cookie_issues.append("missing HttpOnly")
                if not url.startswith("https://") and "secure" not in cookie.lower():
                    cookie_issues.append("missing Secure")
            findings.append(ScanFinding(
                title=f"HTTP request log captured ({len(log)} requests)",
                description=f"Captured {len(log)} request/response pair(s) starting at {entry_url}.",
                severity="info",
                target_url=url,
                evidence={
                    "requests": [
                        {"method": e.get("method"), "url": e.get("url"), "status": e.get("status"), "length": e.get("content_length")}
                        for e in log
                    ],
                    "server": headers.get("server", ""),
                    "cookie_issues": sorted(set(cookie_issues)),
                },
                source_scanner=self.name,
                source_finding_id=f"httplog_{url}",
                tags=["http", "logger"],
            ))
            if cookie_issues:
                findings.append(ScanFinding(
                    title="Insecure cookie attributes",
                    description="Cookies were set without secure attributes: " + ", ".join(sorted(set(cookie_issues))),
                    severity="low",
                    target_url=url,
                    evidence={"issues": sorted(set(cookie_issues))},
                    remediation="Set HttpOnly and Secure on session cookies.",
                    source_scanner=self.name,
                    source_finding_id=f"cookies_{url}",
                    tags=["http", "cookies", "hardening"],
                ))
        else:
            findings.append(ScanFinding(
                title="HTTP request logging failed",
                description=f"Could not capture requests for {entry_url}.",
                severity="info",
                target_url=url,
                evidence={"notes": notes},
                source_scanner=self.name,
                source_finding_id=f"httplog_none_{url}",
                tags=["http", "logger"],
            ))

        completed = datetime.utcnow()
        return ScanResult(
            scan_id=options.get("scan_id", "unknown"),
            scanner_name=self.name,
            status="completed",
            findings=findings,
            raw_output=json.dumps(log, indent=2, default=str)[:200000],
            started_at=started,
            completed_at=completed,
            duration_seconds=int((completed - started).total_seconds()),
            metadata={"url": url, "requests": len(log), "notes": notes},
        )


# Register scanners
from services.scanner_base import ScannerRegistry  # noqa: E402

for _cls in (
    SubdomainScanner, ReconScanner, PasswordAuditorScanner,
    GoogleHackingScanner, PeopleHunterScanner, DomainFinderScanner,
    VHostScanner, URLFuzzerScanner, HTTPRequestLoggerScanner,
):
    ScannerRegistry.register(_cls())
