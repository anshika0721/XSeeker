#!/usr/bin/env python3

import requests
import re
import json
import logging
import hashlib
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qsl, urlunparse, urlencode
from typing import List, Dict, Set, Optional, NamedTuple
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import colorama
from colorama import Fore, Style
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from xss_payloads import XSSPayloads
from report_generator import ReportGenerator
import time
from datetime import datetime

# Initialize colorama
colorama.init()

class Vulnerability(NamedTuple):
    url: str
    parameter: str
    vuln_type: str
    payload: str
    evidence: str
    context: str
    status_code: int
    response_length: int
    headers: Dict
    screenshot: Optional[bytes]
    timestamp: str
    severity: str
    vulnerability_id: str

    def __hash__(self):
        return hash(self.vulnerability_id)

    def __eq__(self, other):
        if not isinstance(other, Vulnerability):
            return False
        return self.vulnerability_id == other.vulnerability_id

class XSSScanner:
    def __init__(self, target_url: str, config: Dict = None):
        self.target_url = target_url
        self.config = config or {}
        self.session = requests.Session()
        self.vulnerabilities = set()
        self.visited_urls = set()
        self.payloads = XSSPayloads()
        self.report_generator = ReportGenerator()
        self.setup_logging()
        self.setup_browser()
        # Add rate limiting configuration
        self.rate_limit_delay = self.config.get('rate_limit_delay', 1.0)  # Default 1 second between requests
        self.max_retries = self.config.get('max_retries', 3)  # Default 3 retries
        self.last_request_time = 0

    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('xss_scan.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def setup_browser(self):
        """Setup headless Chrome browser for screenshots"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            
            # Try to use Chromium first
            try:
                service = Service('/usr/bin/chromedriver')
                self.browser = webdriver.Chrome(service=service, options=chrome_options)
            except Exception as e:
                self.logger.warning(f"Failed to use system Chromium: {str(e)}")
                self.logger.info("Falling back to webdriver-manager...")
                service = Service(ChromeDriverManager().install())
                self.browser = webdriver.Chrome(service=service, options=chrome_options)
                
        except Exception as e:
            self.logger.error(f"Failed to initialize browser: {str(e)}")
            self.logger.warning("Screenshots will not be available")
            self.browser = None

    def capture_screenshot(self, url: str, payload: str) -> Optional[bytes]:
        """Capture screenshot of the page with XSS payload"""
        if not self.browser:
            return None
            
        try:
            # Add payload to URL parameters
            parsed_url = urlparse(url)
            params = dict(parse_qsl(parsed_url.query))
            params['test'] = payload
            test_url = urlunparse((
                parsed_url.scheme,
                parsed_url.netloc,
                parsed_url.path,
                parsed_url.params,
                urlencode(params),
                parsed_url.fragment
            ))
            
            self.browser.get(test_url)
            # Wait for potential XSS execution
            time.sleep(2)
            return self.browser.get_screenshot_as_png()
        except Exception as e:
            self.logger.error(f"Error capturing screenshot: {str(e)}")
            return None

    def scan_url(self, url: str) -> None:
        """Scan a single URL for XSS vulnerabilities"""
        if url in self.visited_urls:
            return
        
        self.visited_urls.add(url)
        self.logger.info(f"Scanning URL: {url}")
        
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all forms
            forms = soup.find_all('form')
            for form in forms:
                self.test_form_xss(url, form)
            
            # Find all input fields
            inputs = soup.find_all('input')
            for input_field in inputs:
                self.test_input_xss(url, input_field)
            
            # Find all links
            links = soup.find_all('a')
            for link in links:
                self.test_link_xss(url, link)
                
        except Exception as e:
            self.logger.error(f"Error scanning {url}: {str(e)}")

    def _rate_limit(self):
        """Implement rate limiting between requests"""
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        if time_since_last_request < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - time_since_last_request)
        self.last_request_time = time.time()

    def _make_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with rate limiting and retries"""
        for attempt in range(self.max_retries):
            try:
                self._rate_limit()
                response = self.session.request(method, url, **kwargs)
                return response
            except requests.exceptions.RequestException as e:
                if attempt == self.max_retries - 1:
                    self.logger.error(f"Request failed after {self.max_retries} attempts: {str(e)}")
                    return None
                time.sleep(self.rate_limit_delay * (attempt + 1))  # Exponential backoff
        return None

    def test_form_xss(self, url: str, form: BeautifulSoup) -> None:
        """Test form for XSS vulnerabilities"""
        try:
            form_action = form.get('action', '')
            form_method = form.get('method', 'get').lower()
            
            if not form_action:
                form_action = url
                
            form_url = urljoin(url, form_action)
            
            # Get all input fields in the form
            inputs = form.find_all(['input', 'textarea'])
            for input_field in inputs:
                input_name = input_field.get('name', '')
                if not input_name:
                    continue
                    
                for payload in self.payloads.get_all_payloads():
                    try:
                        payload_str = str(payload)
                        if form_method == 'get':
                            # For GET requests
                            test_params = {str(input_name): payload_str}
                            response = self._make_request('GET', form_url, params=test_params)
                        else:
                            # For POST requests
                            data = {}
                            for field in inputs:
                                name = field.get('name', '')
                                if name:
                                    if name == input_name:
                                        data[str(name)] = payload_str
                                    else:
                                        value = field.get('value', '')
                                        if value is None:
                                            value = ''
                                        data[str(name)] = str(value)
                            
                            response = self._make_request('POST', form_url, data=data)
                        
                        if response and self.check_xss_success(response, payload_str):
                            self.report_vulnerability(url, 'form', payload_str, response, input_name)
                            
                    except Exception as e:
                        self.logger.error(f"Error testing form XSS: {str(e)}")
                        self.logger.debug(f"Form URL: {form_url}, Input: {input_name}, Payload: {payload}")
        except Exception as e:
            self.logger.error(f"Error processing form: {str(e)}")

    def test_input_xss(self, url: str, input_field: BeautifulSoup) -> None:
        """Test input field for XSS vulnerabilities"""
        try:
            input_name = input_field.get('name', '')
            if not input_name:
                return
                
            for payload in self.payloads.get_all_payloads():
                try:
                    # Test GET request
                    params = {}
                    params[str(input_name)] = str(payload)
                    response = self.session.get(url, params=params)
                    
                    if self.check_xss_success(response, payload):
                        self.report_vulnerability(url, 'input', payload, response, input_name)
                        
                except Exception as e:
                    self.logger.error(f"Error testing input XSS: {str(e)}")
                    self.logger.debug(f"URL: {url}, Input: {input_name}, Payload: {payload}")
        except Exception as e:
            self.logger.error(f"Error processing input field: {str(e)}")

    def test_link_xss(self, url: str, link: BeautifulSoup) -> None:
        """Test link for XSS vulnerabilities"""
        try:
            href = link.get('href', '')
            if not href:
                return
                
            # Skip mailto: links and other non-http(s) protocols
            if href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
                return
                
            # Extract parameters from the link
            parsed_url = urlparse(href)
            params = dict(parse_qsl(parsed_url.query))
            
            for param_name in params.keys():
                for payload in self.payloads.get_all_payloads():
                    try:
                        payload_str = str(payload)
                        test_url = urljoin(url, href)
                        # Test GET request with single parameter
                        test_params = {str(param_name): payload_str}
                        response = self._make_request('GET', test_url, params=test_params)
                        
                        if response and self.check_xss_success(response, payload_str):
                            self.report_vulnerability(url, 'link', payload_str, response, param_name)
                            
                    except Exception as e:
                        self.logger.error(f"Error testing link XSS: {str(e)}")
                        self.logger.debug(f"URL: {test_url}, Parameter: {param_name}, Payload: {payload}")
        except Exception as e:
            self.logger.error(f"Error processing link: {str(e)}")

    def check_xss_success(self, response: requests.Response, payload: str) -> bool:
        """Check if XSS payload was successful with strict validation"""
        try:
            # Normalize the response text and payload for comparison
            response_text = response.text.lower()
            normalized_payload = payload.lower()
            
            # Check for reflected payload (exact match)
            if payload in response.text:
                # Verify the payload is not in a comment or string
                payload_index = response.text.find(payload)
                if payload_index != -1:
                    # Check if payload is inside HTML comment
                    comment_start = response.text.rfind('<!--', 0, payload_index)
                    comment_end = response.text.find('-->', payload_index)
                    if comment_start != -1 and comment_end != -1 and comment_start < payload_index < comment_end:
                        return False
                    
                    # Check if payload is inside a script tag string
                    script_start = response.text.rfind('<script', 0, payload_index)
                    if script_start != -1:
                        script_end = response.text.find('</script>', payload_index)
                        if script_end != -1:
                            script_content = response.text[script_start:script_end]
                            if payload in script_content and not any(payload in line.strip() for line in script_content.split('\n')):
                                return False
                
                return True
                
            # Check for split/obfuscated payloads with strict validation
            if '<scr' in response_text and 'ipt>' in response_text:
                script_start = response_text.find('<scr')
                script_end = response_text.find('ipt>', script_start)
                if script_start != -1 and script_end != -1:
                    # Get the full context
                    context_start = max(0, script_start - 50)
                    context_end = min(len(response_text), script_end + 50)
                    context = response_text[context_start:context_end]
                    
                    # Check if it's a false positive (e.g., in a string or comment)
                    if '<!--' in context and '-->' in context:
                        return False
                        
                    # Check if it's part of a legitimate script tag
                    if 'script' in context and not any(c in context for c in ['\n', '\t', '\r', '\x00', '\x0A', '\x0D', '\x09', '\x0C', '\x0B', '\x0E', '\x0F', '\x1A', '\x20']):
                        return False
                    
                    # Verify the split is intentional
                    between_parts = response_text[script_start+4:script_end]
                    if any(c in between_parts for c in ['\n', '\t', '\r', '\x00', '\x0A', '\x0D', '\x09', '\x0C', '\x0B', '\x0E', '\x0F', '\x1A', '\x20']):
                        # Additional validation for split payloads
                        if 'alert(' in response_text[script_end:script_end+100] or 'onerror=' in response_text[script_end:script_end+100]:
                            return True
            
            # Check for common XSS indicators with context validation
            xss_indicators = [
                ('<script>', '</script>'),
                ('alert(', ')'),
                ('onerror=', '>'),
                ('onload=', '>'),
                ('onclick=', '>'),
                ('onmouseover=', '>'),
                ('onfocus=', '>'),
                ('ontoggle=', '>'),
                ('onstart=', '>'),
                ('onloadstart=', '>'),
                ('javascript:', ';'),
            ]
            
            for start_indicator, end_indicator in xss_indicators:
                if start_indicator in response_text:
                    # Get the context around the indicator
                    indicator_index = response_text.find(start_indicator)
                    context_start = max(0, indicator_index - 50)
                    context_end = min(len(response_text), indicator_index + 100)
                    context = response_text[context_start:context_end]
                    
                    # Skip if in HTML comment
                    if '<!--' in context and '-->' in context:
                        continue
                        
                    # Skip if in a string
                    if context.count('"') % 2 == 1 or context.count("'") % 2 == 1:
                        continue
                    
                    # Verify the indicator is properly terminated
                    if end_indicator in response_text[indicator_index:indicator_index+100]:
                        return True
                    
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking XSS success: {str(e)}")
            return False

    def get_evidence_snippet(self, response: requests.Response, payload: str) -> str:
        """Get a snippet of the response containing the payload"""
        try:
            # Find the payload in the response
            payload_index = response.text.find(payload)
            if payload_index != -1:
                # Get context around the payload
                start = max(0, payload_index - 100)
                end = min(len(response.text), payload_index + len(payload) + 100)
                return response.text[start:end]
            
            # If exact payload not found, look for split/obfuscated versions
            if '<scr' in response.text and 'ipt>' in response.text:
                script_start = response.text.find('<scr')
                script_end = response.text.find('ipt>', script_start)
                if script_start != -1 and script_end != -1:
                    # Get context around the split script tag
                    start = max(0, script_start - 100)
                    end = min(len(response.text), script_end + 4 + 100)
                    return response.text[start:end]
            
            # If no specific evidence found, return a portion of the response
            return response.text[:200] + "..."
            
        except Exception as e:
            self.logger.error(f"Error getting evidence snippet: {str(e)}")
            return "Error getting evidence snippet"

    def generate_vulnerability_id(self, url: str, parameter: str, vuln_type: str) -> str:
        """Generate a unique vulnerability ID based on URL, parameter, and type"""
        unique_string = f"{url}|{parameter}|{vuln_type}"
        return hashlib.md5(unique_string.encode()).hexdigest()[:8]

    def is_duplicate_vulnerability(self, url: str, parameter: str, vuln_type: str) -> bool:
        """Check if a vulnerability is a duplicate"""
        vuln_id = self.generate_vulnerability_id(url, parameter, vuln_type)
        return any(v.vulnerability_id == vuln_id for v in self.vulnerabilities)

    def get_vulnerability_context(self, response: requests.Response, payload: str) -> str:
        """Extract the context around the vulnerability"""
        try:
            text = response.text
            payload_index = text.find(payload)
            if payload_index == -1:
                return "Context not available"
            
            # Get 100 characters before and after the payload
            start = max(0, payload_index - 100)
            end = min(len(text), payload_index + len(payload) + 100)
            context = text[start:end]
            
            # Clean up the context
            context = re.sub(r'\s+', ' ', context)
            return context.strip()
        except Exception as e:
            self.logger.error(f"Error getting vulnerability context: {str(e)}")
            return "Context extraction failed"

    def report_vulnerability(self, url: str, vuln_type: str, payload: str, response: requests.Response, parameter: str) -> None:
        """Report a vulnerability with improved organization"""
        if self.is_duplicate_vulnerability(url, parameter, vuln_type):
            return

        vuln_id = self.generate_vulnerability_id(url, parameter, vuln_type)
        evidence = self.get_evidence_snippet(response, payload)
        context = self.get_vulnerability_context(response, payload)
        
        # Determine severity based on context and payload
        severity = "high" if any(x in payload.lower() for x in ["script", "onerror", "onload"]) else "medium"
        
        try:
            vulnerability = Vulnerability(
                url=str(url),
                parameter=str(parameter),
                vuln_type=str(vuln_type),
                payload=str(payload),
                evidence=str(evidence),
                context=str(context),
                status_code=int(response.status_code),
                response_length=int(len(response.content)),
                headers=dict(response.headers),
                screenshot=self.capture_screenshot(url, payload),
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                severity=str(severity),
                vulnerability_id=str(vuln_id)
            )
            
            self.vulnerabilities.add(vulnerability)
            self.logger.info(f"Found XSS vulnerability in {url} (Parameter: {parameter}, Type: {vuln_type})")
        except Exception as e:
            self.logger.error(f"Error creating vulnerability object: {str(e)}")

    def generate_report(self) -> None:
        """Generate detailed reports"""
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No XSS vulnerabilities found{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.YELLOW}[*] Generating XSS Scan Reports{Style.RESET_ALL}")
        
        try:
            # Generate HTML report
            html_report = self.report_generator.generate_report(self.target_url, self.vulnerabilities)
            if html_report:
                print(f"{Fore.GREEN}[+] HTML report saved to: {html_report}{Style.RESET_ALL}")
            
            # Generate JSON report
            json_report = self.report_generator.save_json_report(self.vulnerabilities)
            if json_report:
                print(f"{Fore.GREEN}[+] JSON report saved to: {json_report}{Style.RESET_ALL}")
                
        except Exception as e:
            self.logger.error(f"Error generating reports: {str(e)}")
            print(f"{Fore.RED}[!] Error generating reports. Check the log file for details.{Style.RESET_ALL}")

    def start_scan(self) -> None:
        """Start the XSS scanning process"""
        print(f"{Fore.CYAN}[*] Starting XSS scan for {self.target_url}{Style.RESET_ALL}")
        
        try:
            self.scan_url(self.target_url)
            self.generate_report()
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
            self.generate_report()
            
        except Exception as e:
            self.logger.error(f"Error during scan: {str(e)}")
            self.generate_report()
            
        finally:
            # Cleanup
            if self.browser:
                self.browser.quit()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced XSS Vulnerability Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--config', help='Path to configuration file')
    
    args = parser.parse_args()
    
    scanner = XSSScanner(args.url)
    scanner.start_scan() 
