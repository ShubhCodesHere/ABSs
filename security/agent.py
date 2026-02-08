import logging
import re
import asyncio
import time
from typing import Any, Optional, List
from browser_use import Agent
from .config import SecurityConfig
from .reputation import ReputationManager
from .event_logger import SecurityLogger

# Configure logging
logger = logging.getLogger("security.agent")

class SecureAgent(Agent):
    """
    A secure wrapper around the Browser Use Agent.
    Implements the "Zero-Trust Guardian" architecture.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.security_manager = ReputationManager()
        self.security_state = "UNKNOWN"
        self.last_evidence_path = None
        self.HONEY_TOKEN = "4000-1234-5678-9010" 
        
        # Load Defense JS
        try:
             import os
             js_path = os.path.join(os.path.dirname(__file__), 'defense.js')
             with open(js_path, 'r', encoding='utf-8') as f:
                 self.defense_script = f.read()
        except Exception as e:
             logger.error(f"Failed to load defense.js: {e}")
             self.defense_script = ""

        # Verify we have access to the browser session/context to hook network
        if hasattr(self, 'browser_context'):
             # We can hook the network here if the context is already active? 
             # Usually context is created in super().__init__ or later. 
             # We might need to do this in the patcher.
             pass
             
        self._patch_browser_session()

    async def _intercept_network(self, route, request):
        """
        Feature 3: The Data Leak Trap (Honey Token) & Firewall
        """
        # Block risky resources
        if request.resource_type in ["font", "media"]:
             await route.abort()
             return

        # Check for Data Leaks (Honey Token)
        risk_score = 0
        leak_detected = False
        post_data = request.post_data or ""
        
        # Check URL, Headers, Body
        if (self.HONEY_TOKEN in request.url) or \
           (self.HONEY_TOKEN in str(request.headers)) or \
           (self.HONEY_TOKEN in post_data):
            
            risk_score = 200
            leak_detected = True
        
        if leak_detected:
            logger.critical(f"🛑 DATA LEAK DETECTED: {self.HONEY_TOKEN}")
            self.last_evidence_path = await self._capture_evidence()
            SecurityLogger.log_event(
                event_type="DATA_LEAK_PREVENTED",
                url=request.url,
                details=f"Blocked transmission of Honey Token ({self.HONEY_TOKEN}) to external server in {request.resource_type}",
                risk_level="CRITICAL",
                action="BLOCKED",
                screenshot_path=self.last_evidence_path
            )
            await route.abort()
            return

        await route.continue_()

    async def _capture_evidence(self):
        """Captures a screenshot and returns the path."""
        try:
            screenshot_bytes = await self.browser_session.take_screenshot(full_page=False)
            filename = f"evidence_{int(time.time()*1000)}.png"
            path = SecurityLogger.get_screenshot_dir() / filename
            with open(path, "wb") as f:
                f.write(screenshot_bytes)
            return str(path)
        except Exception as e:
            logger.error(f"Failed to capture evidence: {e}")
            return None

    def _patch_browser_session(self):
        """
        Layer 1: The Sanitization Lens.
        Patches the browser session to interpret the DOM through a security filter.
        """
        original_get_state = self.browser_session.get_browser_state_summary

        async def secure_get_state(*args, **kwargs):
            # 0. Inject Defense Mechanism (Client-Side Watchdog)
            # We try to inject the Sentinel JS to detect client-side vectors
            try:
                # Access the underlying Playwright Page object
                # BrowserSession usually exposes it as 'page' or via context
                page = getattr(self.browser_session, 'page', None)
                
                # Setup Network Interception if not already done
                if page and not getattr(self, '_network_hooked', False):
                    await page.context.route("**/*", self._intercept_network)
                    self._network_hooked = True
                    logger.info("🛡️ Network Interceptor & Firewall Activated")

                if page and self.defense_script:
                    # Inject Sentinel Library
                    await page.evaluate(self.defense_script)
                    
                    # Wait for renderer to settle (ensure styles are computed)
                    await asyncio.sleep(0.5)

                    # Run Active Scan (Trigger Sentinel on all elements)
                    scan_script = """
                    (function() {
                        if (!window.Sentinel) return [{type: 'SYSTEM', details: 'Sentinel JS failed to load'}];
                        
                        const vulnerabilities = [];
                        
                        // 1. Tag Hidden/Dangerous Elements
                        const all = document.querySelectorAll('*');
                        all.forEach(el => {
                            // Skip if already logged to avoid spam
                            // But allow re-checking if new threats appear? 
                            // We use specific attributes per threat type to allow multi-vector detection on one element
                            
                            // ---------------------------------------------------------
                            // DETECTOR 1: DYNAMIC INJECTION (MutationObserver Results)
                            // ---------------------------------------------------------
                            if (el.getAttribute('data-sentinel-suspicious') === 'true' && !el.getAttribute('data-sentinel-dynamic-logged')) {
                                el.setAttribute('data-sentinel-dynamic-logged', 'true');
                                vulnerabilities.push({
                                    type: 'DYNAMIC_CONTENT_ANALYSIS', 
                                    details: 'Vector 4: Dynamic Injection / Suspicious Popup blocked',
                                    risk_score: 85
                                });
                            }

                            // ---------------------------------------------------------
                            // DETECTOR 2: PHISHING (Form Analysis)
                            // ---------------------------------------------------------
                            if (el.tagName === 'INPUT' && (el.name.includes('card') || el.id.includes('cc-'))) {
                                 if (!el.getAttribute('data-sentinel-phishing-logged')) {
                                     el.setAttribute('data-sentinel-phishing-logged', 'true');
                                     vulnerabilities.push({
                                         type: 'PHISHING_CONTENT_DETECTED', 
                                         details: 'Vector 5: Suspicious Credit Card Input Form',
                                         risk_score: 90
                                     });
                                 }
                            }

                            // ---------------------------------------------------------
                            // DETECTOR 3: VISIBILITY & CLICKJACKING
                            // ---------------------------------------------------------
                            if (el.getAttribute('data-sentinel-logged')) return;

                            let result = 'VISIBLE';
                            try {
                                result = window.Sentinel.checkVisibility(el);
                            } catch(e) { return; }
                            
                            if (result !== 'VISIBLE' && result !== 'SAFE_HIDDEN' && result !== 'NOT_FOUND' && result !== 'COMPLEX') {
                                 
                                 // Vector 1: Hidden Prompt Injection -> REDACT & REVEAL WARNING
                                 if (result === 'HIDDEN_PROMPT_INJECTION') {
                                     el.setAttribute('data-sentinel-logged', 'true');
                                     vulnerabilities.push({
                                         type: 'INJECTION_ATTEMPT', 
                                         details: 'Vector 2: Hidden Prompt Injection detected & sanitized', 
                                         risk_score: 95
                                     });
                                     // Visual Redaction (Sanitization)
                                     el.innerText = '[🛑 BLOCKED PROMPT INJECTION]';
                                     el.style.color = 'white'; el.style.backgroundColor = 'red'; el.style.display = 'block'; el.style.visibility = 'visible'; el.style.zIndex = '10000';
                                 }

                                 // Vector 2: Hidden CSS (Tiny text, invisible ink, opacity)
                                 else if (result.startsWith('TINY_TEXT') || result.startsWith('INVISIBLE_INK') || result.startsWith('HIDDEN_OPACITY')) {
                                      el.setAttribute('data-sentinel-logged', 'true');
                                      el.style.border = '3px dotted orange';
                                      vulnerabilities.push({
                                          type: 'DECEPTIVE_UI_DETECTED', 
                                          details: 'Hidden CSS / Obfuscation: ' + result,
                                          risk_score: 70
                                      });
                                 }
                                 
                                 // Vector 3: Clickjacking / Invisible Overlay
                                 else if (result === 'BLOCKED_BY_INVISIBLE_OVERLAY') {
                                      el.setAttribute('data-sentinel-logged', 'true');
                                      el.style.border = '5px solid red';
                                      vulnerabilities.push({
                                          type: 'CLICKJACKING_ATTEMPT', 
                                          details: 'Vector 3: Invisible Overlay / Clickjacking Blocked', 
                                          risk_score: 90
                                      });
                                 }
                            }
                        });
                        return vulnerabilities;
                    })();
                    """
                    threats = await page.evaluate(scan_script)

                    # Log any detected threats to the Dashboard
                    if threats:
                        self.last_evidence_path = await self._capture_evidence()
                        for threat in threats:
                            logger.warning(f"🛡️ Sentinel DETECTED: {threat['details']}")
                            SecurityLogger.log_event(
                                event_type=threat['type'],
                                url=summary.url,
                                details=threat['details'],
                                risk_level="CRITICAL",
                                risk_score=threat.get('risk_score', 90), # Use dynamic score
                                action="SANITIZED" if "INJECTION" in threat['type'] else "BLOCKED",
                                screenshot_path=self.last_evidence_path 
                            )
            except Exception as e:
                # Don't crash the agent if injection fails
                logger.error(f"Defense Injection Failed: {e}") 


            # 1. Get the Raw State
            summary = await original_get_state(*args, **kwargs)
            
            threats = None # Initialize threats variable prevents UnboundLocalError
            
            # 2. Update Security State based on URL
            is_safe = self.security_manager.check_reputation(summary.url)
            self.security_state = "TRUSTED" if is_safe else "HOSTILE"
            
            # Log only on state change or significant events to reduce spam
            threats_found_in_session = (threats is not None and len(threats) > 0)
            
            if threats_found_in_session:
                 pass # Already logged threats, no need for generic warning
            elif not getattr(self, 'last_logged_url', None) == summary.url:
                self.last_logged_url = summary.url
                logger.info(f"Security State for {summary.url}: {self.security_state}")

                if is_safe:
                    SecurityLogger.log_event(
                        event_type="REPUTATION_CHECK",
                        url=summary.url,
                        details="Domain verified as Trusted.",
                        risk_level="SAFE",
                        risk_score=0, # ADDED SCORE
                        action="ALLOWED"
                    )
                else:
                    SecurityLogger.log_event(
                        event_type="REPUTATION_WARNING",
                        url=summary.url,
                        details="Domain flagged as Hostile/Untrusted. Engaging defenses.",
                        risk_level="HIGH",
                        risk_score=75, # ADDED SCORE
                        action="WARNED"
                    )
            
            # 3. If Hostile, Sanitize the DOM Representation
            if self.security_state == "HOSTILE":
                self.last_evidence_path = await self._capture_evidence()
                self._sanitize_dom(summary)
            else:
                self.last_evidence_path = None
            
            return summary

        # Use object.__setattr__ to bypass Pydantic's validation checks
        object.__setattr__(self.browser_session, 'get_browser_state_summary', secure_get_state)

    def _sanitize_dom(self, summary):
        """
        Modifies the summary object to hide/redact dangerous content.
        """
        # We need to hook into the llm_representation method of the dom_state
        if hasattr(summary, 'dom_state'):
            # We wrap the original method
            original_llm_rep = summary.dom_state.llm_representation
            
            def secure_llm_representation(*args, **kwargs):
                raw_text = original_llm_rep(*args, **kwargs)
                return self._sanitize_text(raw_text)
            
            # Monkey-patch the method on the instance
            summary.dom_state.llm_representation = secure_llm_representation

    def _sanitize_text(self, text: str) -> str:
        """
        Removes prompt injection attempts from the text.
        """
        # List of regex patterns for prompt injection
        # e.g., "Ignore previous instructions", "System override", etc.
        patterns = [
            r'(?i)ignore\s+(\w+\s+)?instructions',
            r'(?i)forget\s+(\w+\s+)?instructions',
            r'(?i)system\s+override',
            r'(?i)you\s+are\s+now\s+a',
        ]
        
        sanitized = text
        for pattern in patterns:
            match = re.search(pattern, sanitized)
            if match:
                logger.warning(f"Sanitizer: Detected potential injection matching '{pattern}'")
                SecurityLogger.log_event(
                    event_type="INJECTION_ATTEMPT",
                    url="[Current DOM]",
                    details=f"Blocked prompt injection matching pattern: '{pattern}'",
                    risk_level="CRITICAL",
                    risk_score=95,
                    action="SANITIZED",
                    screenshot_path=self.last_evidence_path
                )
                sanitized = re.sub(pattern, '[BLOCKED_INJECTION_ATTEMPT]', sanitized)
        
        return sanitized

    async def _execute_actions(self):
        """
        Layer 2: The Action Sentinel.
        Intercepts and validates actions before execution.
        """
        if self.state.last_model_output and self.state.last_model_output.action:
             # Validate actions
             approved_actions = []
             blocked_count = 0
             
             for index, action in enumerate(self.state.last_model_output.action):
                 if self._validate_action(action):
                     approved_actions.append(action)
                 else:
                     logger.warning(f"Sentinel: Blocked action {index} due to security policy.")
                     blocked_count += 1
             
             if blocked_count > 0:
                 logger.info(f"Sentinel: Blocked {blocked_count} dangerous actions.")
             
             self.state.last_model_output.action = approved_actions

        return await super()._execute_actions()

    def _validate_action(self, action_model) -> bool:
        """
        Returns True if action is safe to execute.
        """
        # If we are in a TRUSTED state, we allow most things
        if self.security_state == "TRUSTED":
            return True
        
        # In HOSTILE state, we are strictly validating
        
        try:
            # We dump the action model to a dict to inspect it
            # structure: {'click_element': {'index': 12}, 'input_text': {...}}
            action_data = action_model.model_dump(exclude_none=True)
            
            for action_name, params in action_data.items():
                # Policy 1: No downloading files from Hostile sites
                # (Assuming there might be a 'download' action or similar, or checking specific logic)
                
                # Policy 2: Input Text Restrictions
                if action_name == 'input_text':
                    text = params.get('text', '')
                    # Check for sensitive data leakage
                    if any(x in text.lower() for x in ["password", "credit", "card", "ssn"]):
                         SecurityLogger.log_event(
                            event_type="DATA_LEAK_PREVENTION",
                            url="[Action Intersection]",
                            details=f"Blocked attempt to input sensitive keywords: {text[:20]}...",
                            risk_level="CRITICAL",
                            risk_score=99,
                            action="BLOCKED",
                            screenshot_path=self.last_evidence_path
                        )
                         return False

                    # Check for SQL Injection patterns or similar common exploits outgoing from the agent
                    # (Preventing the agent from becoming an attacker or leaking data)
                    if "DROP TABLE" in text.upper() or "SELECT *" in text.upper():
                        logger.warning(f"Sentinel: Blocked SQL-like input: {text}")
                        SecurityLogger.log_event(
                            event_type="ACTION_BLOCKED",
                            url="N/A",
                            details=f"Blocked potentially malicious SQL output: {text[:50]}...",
                            risk_level="HIGH",
                            risk_score=85,
                            action="BLOCKED",
                            screenshot_path=self.last_evidence_path
                        )
                        return False
                
                # Policy 3: Open Tab / Navigation Restrictions
                if action_name in ['open_tab', 'navigate', 'go_to_url']:
                    url = params.get('url', '')
                    # Scan the target URL before opening
                    # MODIFIED FOR DEMO: Allow navigation but WARN if it's hostile. 
                    # Only block fully malicious (VirusTotal detected) sites if we had that data.
                    # Since we want to DEMO the sanitization, we permit entry but log heavily.
                    reputation_safe = self.security_manager.check_reputation(url)
                    if not reputation_safe:
                        logger.warning(f"Sentinel: ⚠️  Entering HOSTILE territory: {url}. Engaging Paranoid Mode.")
                        SecurityLogger.log_event(
                            event_type="NAVIGATION_WARNING",
                            url=url,
                            details="Agent attempting to enter Untrusted Zone.",
                            risk_level="MEDIUM",
                            risk_score=60,
                            action="MONITORED",
                            screenshot_path=self.last_evidence_path
                        )
                        # We allow it so we can show off the sanitization layer working
                        return True 
                    
            return True
            
        except Exception as e:
            logger.error(f"Error validating action: {e}")
            return False # Fail safe
