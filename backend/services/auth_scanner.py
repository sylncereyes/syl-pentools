"""Authenticated scanning with login recording using Playwright"""
import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from pathlib import Path
import uuid

from core.database import get_sync_db
from models.scan import LoginRecording
from sqlalchemy.orm import Session


@dataclass
class LoginStep:
    """Single step in login recording"""
    action: str  # click, fill, navigate, wait, select
    selector: str
    value: str = ""
    url: str = ""
    timestamp: float = 0
    frame_url: str = ""


@dataclass
class LoginRecordingData:
    """Complete login recording"""
    target_url: str
    steps: List[LoginStep]
    selectors: Dict[str, str]  # element_name -> selector
    cookies: Dict[str, str]
    headers: Dict[str, str]
    local_storage: Dict[str, str]
    session_storage: Dict[str, str]
    viewport: Dict[str, int]
    user_agent: str
    browser_version: str


class LoginRecorder:
    """Record login flow using Playwright"""
    
    def __init__(self, recording_id: str, workspace_id: str):
        self.recording_id = recording_id
        self.workspace_id = workspace_id
        self.steps: List[LoginStep] = []
        self.selectors: Dict[str, str] = {}
        self.page = None
        self.context = None
        self.browser = None
        self.start_time = datetime.utcnow().timestamp()
    
    async def start(self, target_url: str, viewport: Dict[str, int] = None) -> str:
        """Start recording session"""
        from playwright.async_api import async_playwright
        
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=False,  # Show browser for manual recording
            args=['--no-sandbox', '--disable-setuid-sandbox']
        )
        
        viewport = viewport or {"width": 1280, "height": 720}
        self.context = await self.browser.new_context(
            viewport=viewport,
            record_har_path=f"/tmp/recording_{self.recording_id}.har",
        )
        
        # Enable request/response capture
        self.context.on("request", self._on_request)
        self.context.on("response", self._on_response)
        
        self.page = await self.context.new_page()
        
        # Navigate to target
        await self.page.goto(target_url, wait_until="networkidle")
        
        # Inject recording script
        await self.page.add_init_script("""
            window.__login_recorder = {
                steps: [],
                selectors: {},
                recordStep: function(action, selector, value, frameUrl) {
                    this.steps.push({
                        action,
                        selector,
                        value,
                        url: window.location.href,
                        timestamp: Date.now() / 1000,
                        frameUrl: frameUrl || window.location.href
                    });
                }
            };
            
            // Override click
            const originalClick = Element.prototype.click;
            Element.prototype.click = function() {
                const selector = this.getAttribute('data-testid') || 
                                this.id ? '#' + this.id : 
                                this.className ? '.' + this.className.split(' ')[0] : 
                                this.tagName.toLowerCase();
                window.__login_recorder.recordStep('click', selector, '', window.location.href);
                return originalClick.apply(this, arguments);
            };
            
            // Override fill/input
            const originalValueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
            Object.defineProperty(HTMLInputElement.prototype, 'value', {
                set: function(value) {
                    const selector = this.getAttribute('data-testid') || 
                                    this.id ? '#' + this.id : 
                                    this.className ? '.' + this.className.split(' ')[0] : 
                                    this.tagName.toLowerCase();
                    window.__login_recorder.recordStep('fill', selector, value, window.location.href);
                    return originalValueSetter.call(this, value);
                }
            });
        """)
        
        return "recording_started"
    
    def _on_request(self, request):
        """Capture request headers"""
        pass
    
    def _on_response(self, response):
        """Capture response"""
        pass
    
    async def stop(self) -> LoginRecordingData:
        """Stop recording and extract data"""
        # Extract recorded steps from page
        steps_data = await self.page.evaluate("window.__login_recorder.steps")
        self.steps = [LoginStep(**s) for s in steps_data]
        
        # Extract cookies
        cookies = await self.context.cookies()
        cookies_dict = {c['name']: c['value'] for c in cookies}
        
        # Extract localStorage and sessionStorage
        local_storage = await self.page.evaluate("() => JSON.stringify(localStorage)")
        session_storage = await self.page.evaluate("() => JSON.stringify(sessionStorage)")
        
        # Get headers from a test request
        headers = {}
        try:
            resp = await self.page.goto("about:blank")
            headers = dict(resp.headers) if resp else {}
        except:
            pass
        
        # Get user agent and browser version
        user_agent = await self.page.evaluate("navigator.userAgent")
        browser_version = await self.browser.version()
        
        # Get viewport
        viewport = await self.page.evaluate("() => ({width: window.innerWidth, height: window.innerHeight})")
        
        recording = LoginRecordingData(
            target_url=self.page.url,
            steps=self.steps,
            selectors=self.selectors,
            cookies=cookies_dict,
            headers=headers,
            local_storage=json.loads(local_storage) if local_storage else {},
            session_storage=json.loads(session_storage) if session_storage else {},
            viewport=viewport,
            user_agent=user_agent,
            browser_version=browser_version,
        )
        
        # Cleanup
        await self.context.close()
        await self.browser.close()
        await self.playwright.stop()
        
        return recording
    
    async def save_to_db(self, name: str, created_by: str) -> str:
        """Save recording to database"""
        recording_data = await self.stop()
        
        db: Session = next(get_sync_db())
        try:
            recording = LoginRecording(
                id=self.recording_id,
                workspace_id=self.workspace_id,
                name=name,
                target_url=recording_data.target_url,
                steps=[asdict(s) for s in recording_data.steps],
                selectors=recording_data.selectors,
                cookies=recording_data.cookies,
                headers=recording_data.headers,
                local_storage=recording_data.local_storage,
                session_storage=recording_data.session_storage,
                viewport=recording_data.viewport,
                user_agent=recording_data.user_agent,
                browser_version=recording_data.browser_version,
                created_by=created_by,
            )
            db.add(recording)
            db.commit()
            return self.recording_id
        finally:
            db.close()


class AuthenticatedScanner:
    """Run scans with authenticated session"""
    
    def __init__(self, login_recording_id: str):
        self.login_recording_id = login_recording_id
        self.recording: Optional[LoginRecording] = None
        self.playwright = None
        self.browser = None
        self.context = None
        self.page = None
    
    async def load_recording(self, db: Session) -> bool:
        """Load login recording from database"""
        self.recording = db.query(LoginRecording).filter(
            LoginRecording.id == self.login_recording_id
        ).first()
        return self.recording is not None
    
    async def create_authenticated_session(self) -> bool:
        """Create browser session with recorded authentication"""
        if not self.recording:
            return False
        
        from playwright.async_api import async_playwright
        
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(headless=True)
        
        # Restore context with cookies and storage
        self.context = await self.browser.new_context(
            viewport=self.recording.viewport,
            user_agent=self.recording.user_agent,
        )
        
        # Add cookies
        if self.recording.cookies:
            cookies = [
                {"name": k, "value": v, "domain": self._extract_domain(self.recording.target_url)}
                for k, v in self.recording.cookies.items()
            ]
            await self.context.add_cookies(cookies)
        
        self.page = await self.context.new_page()
        
        # Set localStorage and sessionStorage
        if self.recording.local_storage:
            await self.page.evaluate(f"""
                Object.assign(localStorage, {json.dumps(self.recording.local_storage)});
            """)
        if self.recording.session_storage:
            await self.page.evaluate(f"""
                Object.assign(sessionStorage, {json.dumps(self.recording.session_storage)});
            """)
        
        # Set custom headers
        if self.recording.headers:
            await self.context.set_extra_http_headers(self.recording.headers)
        
        # Navigate to target to verify auth works
        try:
            await self.page.goto(self.recording.target_url, wait_until="networkidle")
            return True
        except Exception:
            return False
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        from urllib.parse import urlparse
        return urlparse(url).netloc
    
    async def scan_with_auth(self, scanner, target: str, options: Dict) -> Any:
        """Run scanner with authenticated session"""
        if not self.page:
            return None
        
        # Navigate to target
        await self.page.goto(target, wait_until="networkidle")
        
        # Extract current cookies/headers for scanner
        cookies = await self.context.cookies()
        cookie_header = "; ".join([f"{c['name']}={c['value']}" for c in cookies])
        
        # Add to options
        options['cookies'] = cookie_header
        options['headers'] = options.get('headers', {})
        options['headers']['Cookie'] = cookie_header
        
        return await scanner.scan(target, options)
    
    async def close(self):
        """Cleanup"""
        if self.context:
            await self.context.close()
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()


# Helper functions for API
async def start_login_recording(recording_id: str, workspace_id: str, target_url: str) -> str:
    """Start a new login recording session"""
    recorder = LoginRecorder(recording_id, workspace_id)
    await recorder.start(target_url)
    return recording_id


async def stop_login_recording(recording_id: str, workspace_id: str, name: str, created_by: str) -> str:
    """Stop and save login recording"""
    # We need to store the recorder instance somewhere accessible
    # In production, use Redis or in-memory store with recording_id as key
    pass


def get_login_recording(recording_id: str) -> Optional[LoginRecording]:
    """Get login recording from database"""
    db: Session = next(get_sync_db())
    try:
        return db.query(LoginRecording).filter(LoginRecording.id == recording_id).first()
    finally:
        db.close()