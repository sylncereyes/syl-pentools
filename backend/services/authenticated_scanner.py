"""
Authenticated Scanner Service using Playwright for behind-login scanning.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from uuid import UUID, uuid4

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page, Playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

from celery import shared_task
from core.config import settings

logger = logging.getLogger(__name__)


class AuthType(str, Enum):
    """Authentication type."""
    FORM = "form"           # Username/password form
    SSO_SAML = "sso_saml"   # SAML SSO
    SSO_OIDC = "sso_oidc"   # OIDC SSO
    MFA_TOTP = "mfa_totp"   # TOTP MFA
    COOKIE = "cookie"       # Pre-authenticated cookies
    HEADER = "header"       # Custom header authentication
    NONE = "none"           # No authentication


@dataclass
class AuthenticationConfig:
    """Configuration for authentication."""
    auth_type: AuthType = AuthType.NONE
    
    # Form authentication
    login_url: Optional[str] = None
    username_selector: str = "input[name='username'], input[name='email'], input[type='email']"
    password_selector: str = "input[name='password'], input[type='password']"
    submit_selector: str = "button[type='submit'], input[type='submit']"
    username: Optional[str] = None
    password: Optional[str] = None
    
    # SSO
    sso_provider: Optional[str] = None
    sso_config: Dict[str, Any] = field(default_factory=dict)
    
    # MFA
    mfa_type: Optional[str] = None
    mfa_secret: Optional[str] = None
    
    # Cookie/Header auth
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    
    # Session management
    session_file: Optional[str] = None
    reuse_session: bool = True
    session_timeout: int = 3600  # seconds
    
    # Verification
    verify_selector: Optional[str] = None  # Element that confirms logged in
    verify_url: Optional[str] = None       # URL to check after login
    
    # Multi-step login
    extra_steps: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AuthenticatedSession:
    """Represents an authenticated browser session."""
    context: BrowserContext
    page: Page
    cookies: List[Dict[str, Any]]
    created_at: datetime
    last_used: datetime
    auth_config: AuthenticationConfig
    
    def is_expired(self, timeout: int) -> bool:
        """Check if session has expired."""
        elapsed = (datetime.now(timezone.utc) - self.last_used).total_seconds()
        return elapsed > timeout


class AuthenticatedScanner:
    """
    Playwright-based authenticated scanner for behind-login applications.
    
    Supports:
    - Form-based authentication (username/password)
    - SAML/OIDC SSO
    - TOTP MFA
    - Cookie/session reuse
    - Custom header authentication
    - Multi-step login flows
    """
    
    def __init__(self, auth_config: AuthenticationConfig):
        self.auth_config = auth_config
        self.playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None
        self.session: Optional[AuthenticatedSession] = None
        self._session_dir = Path(settings.REPORTS_DIR) / "auth_sessions"
        self._session_dir.mkdir(parents=True, exist_ok=True)
        
    async def __aenter__(self):
        await self.start()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        
    async def start(self) -> None:
        """Initialize Playwright and browser."""
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError("Playwright not installed. Run: pip install playwright && playwright install")
            
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--no-first-run",
                "--no-zygote",
                "--single-process",
            ]
        )
        logger.info("Playwright browser started")
        
    async def close(self) -> None:
        """Close browser and playwright."""
        if self.session:
            await self.save_session()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        logger.info("Playwright closed")
        
    async def authenticate(self) -> AuthenticatedSession:
        """Perform authentication based on config."""
        if not self.browser:
            await self.start()
            
        # Try to load existing session
        if self.auth_config.reuse_session and self.auth_config.session_file:
            loaded = await self.load_session()
            if loaded and not loaded.is_expired(self.auth_config.session_timeout):
                logger.info("Reusing existing authenticated session")
                self.session = loaded
                return self.session
                
        # Perform authentication based on type
        if self.auth_config.auth_type == AuthType.FORM:
            await self._authenticate_form()
        elif self.auth_config.auth_type == AuthType.SSO_SAML:
            await self._authenticate_saml()
        elif self.auth_config.auth_type == AuthType.SSO_OIDC:
            await self._authenticate_oidc()
        elif self.auth_config.auth_type == AuthType.COOKIE:
            await self._authenticate_cookies()
        elif self.auth_config.auth_type == AuthType.HEADER:
            await self._authenticate_headers()
        else:
            # No authentication - just create context
            await self._create_context()
            
        # Save session if configured
        if self.auth_config.session_file:
            await self.save_session()
            
        return self.session
        
    async def _create_context(self) -> None:
        """Create a new browser context."""
        context = await self.browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            ignore_https_errors=True,
        )
        
        # Add custom headers if configured
        if self.auth_config.headers:
            await context.set_extra_http_headers(self.auth_config.headers)
            
        page = await context.new_page()
        page.set_default_timeout(30000)
        
        self.session = AuthenticatedSession(
            context=context,
            page=page,
            cookies=[],
            created_at=datetime.now(timezone.utc),
            last_used=datetime.now(timezone.utc),
            auth_config=self.auth_config,
        )
        
    async def _authenticate_form(self) -> None:
        """Perform form-based authentication."""
        await self._create_context()
        page = self.session.page
        config = self.auth_config
        
        logger.info(f"Navigating to login page: {config.login_url}")
        await page.goto(config.login_url, wait_until="networkidle")
        
        # Fill username
        logger.info(f"Filling username: {config.username_selector}")
        await page.fill(config.username_selector, config.username or "")
        
        # Fill password
        logger.info(f"Filling password: {config.password_selector}")
        await page.fill(config.password_selector, config.password or "")
        
        # Submit form
        logger.info(f"Submitting form: {config.submit_selector}")
        await page.click(config.submit_selector)
        
        # Wait for navigation or verification
        await page.wait_for_load_state("networkidle")
        
        # Handle extra steps (MFA, etc.)
        for step in config.extra_steps:
            await self._execute_extra_step(step)
            
        # Verify authentication
        if config.verify_selector:
            logger.info(f"Verifying login with selector: {config.verify_selector}")
            await page.wait_for_selector(config.verify_selector, timeout=10000)
        elif config.verify_url:
            logger.info(f"Verifying login at URL: {config.verify_url}")
            await page.wait_for_url(config.verify_url, timeout=10000)
        else:
            # Wait a bit and check if we're still on login page
            await page.wait_for_timeout(2000)
            current_url = page.url
            if config.login_url and config.login_url in current_url:
                raise RuntimeError("Authentication failed - still on login page")
                
        # Update session cookies
        self.session.cookies = await self.session.context.cookies()
        self.session.last_used = datetime.now(timezone.utc)
        logger.info("Form authentication successful")
        
    async def _execute_extra_step(self, step: Dict[str, Any]) -> None:
        """Execute an extra authentication step (e.g., MFA)."""
        page = self.session.page
        step_type = step.get("type")
        
        if step_type == "totp":
            # TOTP MFA step
            selector = step.get("selector", "input[name='totp'], input[name='code'], input[name='mfa']")
            import pyotp
            totp = pyotp.TOTP(self.auth_config.mfa_secret or "")
            code = totp.now()
            logger.info("Filling TOTP code")
            await page.fill(selector, code)
            submit_sel = step.get("submit", "button[type='submit']")
            await page.click(submit_sel)
            await page.wait_for_load_state("networkidle")
            
        elif step_type == "click":
            # Click a button/link
            selector = step.get("selector")
            if selector:
                await page.click(selector)
                await page.wait_for_load_state("networkidle")
                
        elif step_type == "wait":
            # Wait for selector or URL
            selector = step.get("selector")
            url = step.get("url")
            if selector:
                await page.wait_for_selector(selector, timeout=step.get("timeout", 10000))
            elif url:
                await page.wait_for_url(url, timeout=step.get("timeout", 10000))
                
        elif step_type == "fill":
            # Fill additional fields
            selector = step.get("selector")
            value = step.get("value", "")
            if selector:
                await page.fill(selector, value)
                
    async def _authenticate_saml(self) -> None:
        """Perform SAML SSO authentication."""
        await self._create_context()
        page = self.session.page
        config = self.auth_config
        
        # Navigate to SAML login/initiation URL
        saml_url = config.sso_config.get("login_url") or config.login_url
        if saml_url:
            logger.info(f"Navigating to SAML login: {saml_url}")
            await page.goto(saml_url, wait_until="networkidle")
            
            # SAML flow typically redirects to IdP
            # Wait for redirect back to ACS
            await page.wait_for_load_state("networkidle")
            
            # Verify authentication
            if config.verify_selector:
                await page.wait_for_selector(config.verify_selector, timeout=30000)
                
        self.session.cookies = await self.session.context.cookies()
        self.session.last_used = datetime.now(timezone.utc)
        logger.info("SAML authentication completed")
        
    async def _authenticate_oidc(self) -> None:
        """Perform OIDC authentication."""
        await self._create_context()
        page = self.session.page
        config = self.auth_config
        
        # Navigate to OIDC login URL
        oidc_url = config.sso_config.get("login_url") or config.login_url
        if oidc_url:
            logger.info(f"Navigating to OIDC login: {oidc_url}")
            await page.goto(oidc_url, wait_until="networkidle")
            
            # OIDC flow redirects to IdP and back
            await page.wait_for_load_state("networkidle")
            
            # Verify authentication
            if config.verify_selector:
                await page.wait_for_selector(config.verify_selector, timeout=30000)
                
        self.session.cookies = await self.session.context.cookies()
        self.session.last_used = datetime.now(timezone.utc)
        logger.info("OIDC authentication completed")
        
    async def _authenticate_cookies(self) -> None:
        """Authenticate using pre-provided cookies."""
        await self._create_context()
        page = self.session.page
        
        if self.auth_config.cookies:
            logger.info(f"Setting {len(self.auth_config.cookies)} cookies")
            await page.context.add_cookies(self.auth_config.cookies)
            
        self.session.cookies = self.auth_config.cookies
        self.session.last_used = datetime.now(timezone.utc)
        logger.info("Cookie authentication completed")
        
    async def _authenticate_headers(self) -> None:
        """Authenticate using custom headers."""
        await self._create_context()
        page = self.session.page
        
        if self.auth_config.headers:
            logger.info(f"Setting custom headers: {list(self.auth_config.headers.keys())}")
            await page.context.set_extra_http_headers(self.auth_config.headers)
            
        self.session.last_used = datetime.now(timezone.utc)
        logger.info("Header authentication completed")
        
    async def scan_page(self, url: str, wait_for: Optional[str] = None) -> Dict[str, Any]:
        """Scan a page with the authenticated session."""
        if not self.session:
            await self.authenticate()
            
        page = self.session.page
        self.session.last_used = datetime.now(timezone.utc)
        
        logger.info(f"Scanning page: {url}")
        await page.goto(url, wait_until="networkidle")
        
        if wait_for:
            await page.wait_for_selector(wait_for, timeout=10000)
            
        # Get page content
        content = await page.content()
        title = await page.title()
        url_final = page.url
        
        # Get cookies for session persistence
        cookies = await page.context.cookies()
        
        return {
            "url": url_final,
            "title": title,
            "content_length": len(content),
            "cookies": cookies,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
    async def scan_pages(self, urls: List[str], wait_for: Optional[str] = None) -> List[Dict[str, Any]]:
        """Scan multiple pages sequentially."""
        results = []
        for url in urls:
            try:
                result = await self.scan_page(url, wait_for)
                results.append(result)
            except Exception as e:
                logger.error(f"Failed to scan {url}: {e}")
                results.append({
                    "url": url,
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
        return results
        
    async def save_session(self) -> bool:
        """Save session cookies to file."""
        if not self.session or not self.auth_config.session_file:
            return False
            
        try:
            session_file = self._session_dir / self.auth_config.session_file
            session_data = {
                "cookies": self.session.cookies,
                "created_at": self.session.created_at.isoformat(),
                "last_used": datetime.now(timezone.utc).isoformat(),
                "auth_type": self.auth_config.auth_type.value,
            }
            
            with open(session_file, "w") as f:
                json.dump(session_data, f, indent=2)
                
            logger.info(f"Session saved to {session_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save session: {e}")
            return False
            
    async def load_session(self) -> Optional[AuthenticatedSession]:
        """Load session from file."""
        if not self.auth_config.session_file:
            return None
            
        try:
            session_file = self._session_dir / self.auth_config.session_file
            if not session_file.exists():
                return None
                
            with open(session_file, "r") as f:
                session_data = json.load(f)
                
            # Check if session is expired
            last_used = datetime.fromisoformat(session_data["last_used"])
            if (datetime.now(timezone.utc) - last_used).total_seconds() > self.auth_config.session_timeout:
                logger.info("Session expired")
                return None
                
            # Create context and restore cookies
            await self._create_context()
            if session_data.get("cookies"):
                await self.session.context.add_cookies(session_data["cookies"])
                
            self.session.cookies = session_data["cookies"]
            self.session.created_at = datetime.fromisoformat(session_data["created_at"])
            self.session.last_used = datetime.now(timezone.utc)
            
            logger.info(f"Session loaded from {session_file}")
            return self.session
            
        except Exception as e:
            logger.error(f"Failed to load session: {e}")
            return None
            
    async def clear_session(self) -> None:
        """Clear saved session file."""
        if self.auth_config.session_file:
            session_file = self._session_dir / self.auth_config.session_file
            if session_file.exists():
                session_file.unlink()
                logger.info("Session file cleared")


async def create_authenticated_scanner(
    auth_type: str,
    login_url: Optional[str] = None,
    username: Optional[str] = None,
    password: Optional[str] = None,
    session_file: Optional[str] = None,
    **kwargs
) -> AuthenticatedScanner:
    """
    Factory function to create an authenticated scanner.
    
    Args:
        auth_type: Type of authentication (form, sso_saml, sso_oidc, cookie, header, none)
        login_url: URL for login page
        username: Username for form auth
        password: Password for form auth
        session_file: File to persist session cookies
        **kwargs: Additional config options
        
    Returns:
        Configured AuthenticatedScanner instance
    """
    auth_type_enum = AuthType(auth_type.lower())
    
    config = AuthenticationConfig(
        auth_type=auth_type_enum,
        login_url=login_url,
        username=username,
        password=password,
        session_file=session_file,
        **kwargs
    )
    
    return AuthenticatedScanner(config)


# Celery task for authenticated scanning
@shared_task(bind=True, max_retries=2, default_retry_delay=60)
def run_authenticated_scan(
    self,
    scan_id: str,
    target: str,
    auth_config: Dict[str, Any],
    scan_config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Celery task to run an authenticated scan.
    
    Args:
        scan_id: Scan UUID
        target: Target URL to scan
        auth_config: Authentication configuration
        scan_config: Scan configuration (urls to scan, etc.)
        
    Returns:
        Scan results
    """
    
    async def _run_scan():
        from core.database import SyncSessionLocal
        from models.scan import Scan, ScanStatus, ScanLog
        from sqlalchemy.orm import Session
        from datetime import datetime
        
        db: Session = SyncSessionLocal()
        
        try:
            # Get scan record
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                raise ValueError(f"Scan {scan_id} not found")
                
            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            db.commit()
            
            # Log start
            log = ScanLog(scan_id=scan_id, level="info", message="Authenticated scan started", step="auth", progress=0)
            db.add(log)
            db.commit()
            
            # Create scanner
            auth_config_obj = AuthenticationConfig(**auth_config)
            scanner = AuthenticatedScanner(auth_config_obj)
            
            try:
                # Authenticate
                await scanner.authenticate()
                
                # Update progress
                scan.progress = 25.0
                db.commit()
                
                # Scan target and additional URLs
                urls_to_scan = scan_config.get("urls", [target])
                wait_for = scan_config.get("wait_for")
                
                results = await scanner.scan_pages(urls_to_scan, wait_for)
                
                # Update progress
                scan.progress = 75.0
                db.commit()
                
                # Save results
                log = ScanLog(
                    scan_id=scan_id,
                    level="info",
                    message=f"Scanned {len(results)} pages",
                    step="scan",
                    progress=75
                )
                db.add(log)
                db.commit()
                
                # Finalize
                scan.status = ScanStatus.COMPLETED
                scan.completed_at = datetime.utcnow()
                scan.progress = 100.0
                scan.current_step = "completed"
                db.commit()
                
                return {
                    "scan_id": str(scan_id),
                    "status": "completed",
                    "pages_scanned": len(results),
                    "results": results,
                }
                
            finally:
                await scanner.close()
                
        except Exception as e:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = ScanStatus.FAILED
                scan.error_message = str(e)
                scan.completed_at = datetime.utcnow()
                db.commit()
                
            log = ScanLog(
                scan_id=scan_id,
                level="error",
                message=f"Scan failed: {str(e)}",
                step="error",
            )
            db.add(log)
            db.commit()
            
            raise
            
        finally:
            db.close()
    
    return asyncio.run(_run_scan())