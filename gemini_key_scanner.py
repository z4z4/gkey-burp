# Burp Suite Extension: Google API Key Scanner for Gemini Access
# Author: Security Researcher
# Description: Passively scans responses for Google API keys (AIza...) and
#              verifies if they have Gemini API access
#
# Installation:
# 1. Ensure Jython is configured in Burp: Extender > Options > Python Environment
# 2. Download Jython standalone JAR from https://www.jython.org/download
# 3. Set the path to jython-standalone-2.7.x.jar
# 4. Load this extension: Extender > Extensions > Add > Extension Type: Python

from burp import IBurpExtender, IScannerCheck, IScanIssue, IHttpListener
from java.net import URL
from java.io import PrintWriter
from array import array
import re
import threading

class BurpExtender(IBurpExtender, IScannerCheck, IHttpListener):
    
    EXTENSION_NAME = "Gemini API Key Scanner"
    GEMINI_HOST = "generativelanguage.googleapis.com"
    GEMINI_PORT = 443
    GEMINI_PROTOCOL = True  # HTTPS
    
    # Regex for Google API keys
    API_KEY_PATTERN = re.compile(r'AIza[0-9A-Za-z_-]{35}')
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        
        # Set extension name
        callbacks.setExtensionName(self.EXTENSION_NAME)
        
        # Get output stream for logging
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        
        # Track verified keys to avoid duplicate checks
        self._verified_keys = set()
        self._verified_keys_lock = threading.Lock()
        
        # Track keys with Gemini access (for deduplication in issues)
        self._gemini_keys = {}  # key -> models list
        self._gemini_keys_lock = threading.Lock()
        
        # Register as a scanner check AND http listener
        callbacks.registerScannerCheck(self)
        callbacks.registerHttpListener(self)
        
        self._stdout.println("[+] %s loaded successfully" % self.EXTENSION_NAME)
        self._stdout.println("[+] Passively scanning for Google API keys with Gemini access")
        self._stdout.println("[+] Using Burp's HTTP client for verification")
        self._stdout.println("[+] Listening on both Scanner and HTTP Listener interfaces")
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """IHttpListener - called for ALL HTTP traffic through Burp"""
        # Only process responses
        if messageIsRequest:
            return
        
        # Get the response
        response = messageInfo.getResponse()
        if response is None:
            return
        
        # Get URL for logging
        try:
            service = messageInfo.getHttpService()
            host = service.getHost()
        except:
            host = "unknown"
        
        # Process the response
        self.scan_response(response, messageInfo, host, "HTTPListener")
    
    def doPassiveScan(self, baseRequestResponse):
        """IScannerCheck - called by Burp's passive scanner"""
        response = baseRequestResponse.getResponse()
        if response is None:
            return None
        
        try:
            url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
            host = url.getHost()
        except:
            host = "unknown"
        
        issues = self.scan_response(response, baseRequestResponse, host, "PassiveScanner")
        return issues
    
    def scan_response(self, response, messageInfo, host, source):
        """Common method to scan a response for API keys"""
        issues = []
        
        try:
            # Convert response to string
            if isinstance(response, array):
                response_str = ''.join(chr(b & 0xff) for b in response)
            else:
                response_str = self._helpers.bytesToString(response)
        except Exception as e:
            self._stderr.println("[-] Error converting response: %s" % str(e))
            return None
        
        # Debug: log response length
        # self._stdout.println("[DEBUG][%s] Scanning response from %s (%d bytes)" % (source, host, len(response_str)))
        
        # Find all API keys in response
        keys = self.API_KEY_PATTERN.findall(response_str)
        
        if not keys:
            return None
        
        # Deduplicate keys found in this response
        unique_keys = list(set(keys))
        self._stdout.println("[*][%s] Found %d unique API key(s) on %s" % (source, len(unique_keys), host))
        
        for key in unique_keys:
            self._stdout.println("[*] Key found: %s...%s" % (key[:12], key[-4:]))
            
            # Check if we've already verified this key
            with self._verified_keys_lock:
                already_verified = key in self._verified_keys
                if not already_verified:
                    self._verified_keys.add(key)
            
            if already_verified:
                # Check if it's a known Gemini key
                with self._gemini_keys_lock:
                    if key in self._gemini_keys:
                        self._stdout.println("[*] Key already verified as having Gemini access")
                        # Still create an issue for this location
                        try:
                            url = self._helpers.analyzeRequest(messageInfo).getUrl()
                            issue = GeminiKeyIssue(
                                messageInfo.getHttpService(),
                                url,
                                [messageInfo],
                                key,
                                host,
                                models=self._gemini_keys[key],
                                is_duplicate=True
                            )
                            issues.append(issue)
                        except:
                            pass
                continue
            
            # Verify against Gemini API
            self._stdout.println("[*] Verifying key against Gemini API...")
            has_gemini_access, models = self.verify_gemini_access(key)
            
            if has_gemini_access:
                self._stdout.println("[!] CRITICAL: Key has Gemini API access!")
                if models:
                    self._stdout.println("[!] Models available: %s" % ", ".join(models[:5]))
                
                # Track this key as having Gemini access
                with self._gemini_keys_lock:
                    self._gemini_keys[key] = models
                
                # Create a scan issue
                try:
                    url = self._helpers.analyzeRequest(messageInfo).getUrl()
                    issue = GeminiKeyIssue(
                        messageInfo.getHttpService(),
                        url,
                        [messageInfo],
                        key,
                        host,
                        models=models
                    )
                    issues.append(issue)
                    
                    # Also add to Burp's issue list directly
                    self._callbacks.addScanIssue(issue)
                    self._stdout.println("[+] Issue added to Burp!")
                except Exception as e:
                    self._stderr.println("[-] Error creating issue: %s" % str(e))
            else:
                self._stdout.println("[-] Key does not have Gemini access (or restricted)")
        
        return issues if issues else None
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Not used - we only do passive scanning"""
        return None
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Handle duplicate issues for the same key"""
        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1  # Keep existing
        return 0  # Keep both
    
    def verify_gemini_access(self, api_key):
        """
        Verify if an API key has Gemini access by calling the models endpoint.
        Uses Burp's HTTP client for Jython compatibility.
        Returns (has_access, list_of_models)
        """
        try:
            # Build HTTP request
            path = "/v1beta/models?key=" + api_key
            request_str = "GET %s HTTP/1.1\r\n" % path
            request_str += "Host: %s\r\n" % self.GEMINI_HOST
            request_str += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n"
            request_str += "Accept: application/json\r\n"
            request_str += "Connection: close\r\n"
            request_str += "\r\n"
            
            # Convert to bytes
            request_bytes = self._helpers.stringToBytes(request_str)
            
            # Create HTTP service for Google's API
            http_service = self._helpers.buildHttpService(
                self.GEMINI_HOST, 
                self.GEMINI_PORT, 
                self.GEMINI_PROTOCOL
            )
            
            self._stdout.println("[*] Making request to Gemini API...")
            
            # Make the request using Burp's HTTP client
            response = self._callbacks.makeHttpRequest(http_service, request_bytes)
            response_bytes = response.getResponse()
            
            if response_bytes is None:
                self._stderr.println("[-] No response received from Gemini API")
                return False, []
            
            # Analyze response
            response_info = self._helpers.analyzeResponse(response_bytes)
            status_code = response_info.getStatusCode()
            
            self._stdout.println("[*] Gemini API response: HTTP %d" % status_code)
            
            if status_code == 200:
                # Extract body
                body_offset = response_info.getBodyOffset()
                body_bytes = response_bytes[body_offset:]
                body_str = self._helpers.bytesToString(body_bytes)
                
                # Parse model names from JSON
                models = self.extract_models_from_json(body_str)
                self._stdout.println("[*] Found %d Gemini models" % len(models))
                return True, models
            else:
                self._stdout.println("[-] Gemini API returned HTTP %d" % status_code)
            
            return False, []
            
        except Exception as e:
            self._stderr.println("[-] Error verifying key: %s" % str(e))
            import traceback
            self._stderr.println(traceback.format_exc())
            return False, []
    
    def extract_models_from_json(self, json_str):
        """
        Extract model names from JSON response without using json module.
        """
        models = []
        model_pattern = re.compile(r'"name"\s*:\s*"models/([^"]+)"')
        matches = model_pattern.findall(json_str)
        
        for model_name in matches:
            if any(x in model_name.lower() for x in ['gemini', 'flash', 'pro']):
                if model_name not in models:
                    models.append(model_name)
        
        return models


class GeminiKeyIssue(IScanIssue):
    """Custom scan issue for exposed Gemini API keys"""
    
    def __init__(self, http_service, url, http_messages, api_key, host, models=None, is_duplicate=False):
        self._http_service = http_service
        self._url = url
        self._http_messages = http_messages
        self._api_key = api_key
        self._host = host
        self._models = models or []
        self._is_duplicate = is_duplicate
    
    def getUrl(self):
        return self._url
    
    def getIssueName(self):
        return "Exposed Google API Key with Gemini Access"
    
    def getIssueType(self):
        return 0x08000000
    
    def getSeverity(self):
        return "High"
    
    def getConfidence(self):
        return "Certain"
    
    def getIssueBackground(self):
        return """<p>A Google API key was found exposed in the application's response that has been 
        verified to have access to the <b>Google Gemini API</b>.</p>
        
        <p>Based on research by <a href="https://trufflesecurity.com/blog/google-api-keys-werent-secrets-but-then-gemini-changed-the-rules">Truffle Security</a>, 
        Google API keys that were originally deployed for public services (like Google Maps) may have 
        silently gained access to sensitive AI APIs like Gemini when the Generative Language API was 
        enabled on the same GCP project.</p>
        
        <p><b>Impact:</b></p>
        <ul>
            <li><b>Data Exposure:</b> Attackers can access uploaded files and cached content via the /files endpoint</li>
            <li><b>Financial Impact:</b> Unauthorized usage can incur significant charges on the victim's Google Cloud account</li>
            <li><b>AI Abuse:</b> Keys can be used to generate content, potentially for malicious purposes</li>
            <li><b>RAG Data Access:</b> If semantic retrieval is configured, attackers may access proprietary knowledge bases</li>
        </ul>"""
    
    def getRemediationBackground(self):
        return """<p><b>Immediate Actions:</b></p>
        <ul>
            <li>Rotate the exposed API key immediately in the Google Cloud Console</li>
            <li>Review API key restrictions - ensure keys are restricted to only necessary APIs</li>
            <li>Audit the /files endpoint for any sensitive data that may have been exposed</li>
            <li>Review billing for any unauthorized usage charges</li>
        </ul>
        
        <p><b>Long-term Mitigations:</b></p>
        <ul>
            <li>Never embed API keys in client-side JavaScript for sensitive APIs</li>
            <li>Use separate GCP projects for public-facing vs internal APIs</li>
            <li>Implement API key restrictions by service and HTTP referrer</li>
            <li>Regularly audit API key permissions and usage</li>
        </ul>"""
    
    def getIssueDetail(self):
        detail = """<p><b>Exposed API Key:</b></p>
        <pre>%s</pre>
        
        <p><b>Found on host:</b> %s</p>
        
        <p><b>Verification:</b> This key was verified to have Gemini API access by successfully 
        calling the models endpoint:</p>
        <pre>GET https://generativelanguage.googleapis.com/v1beta/models?key=%s</pre>
        """ % (self._api_key, self._host, self._api_key)
        
        if self._models:
            detail += """
            <p><b>Available Gemini Models (%d):</b></p>
            <ul>""" % len(self._models)
            for model in self._models[:10]:
                detail += "<li>%s</li>" % model
            if len(self._models) > 10:
                detail += "<li>... and %d more</li>" % (len(self._models) - 10)
            detail += "</ul>"
        
        detail += """
        <p><b>Proof of Concept:</b></p>
        <pre>curl "https://generativelanguage.googleapis.com/v1beta/models?key=%s"</pre>
        
        <p><b>Check for exposed files:</b></p>
        <pre>curl "https://generativelanguage.googleapis.com/v1beta/files?key=%s"</pre>
        """ % (self._api_key, self._api_key)
        
        if self._is_duplicate:
            detail += """
            <p><i>Note: This key was also found on other pages. This is an additional occurrence.</i></p>
            """
        
        return detail
    
    def getRemediationDetail(self):
        return None
    
    def getHttpMessages(self):
        return self._http_messages
    
    def getHttpService(self):
        return self._http_service
