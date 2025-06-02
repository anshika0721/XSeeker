#!/usr/bin/env python3

import requests
import re
import json
import logging
import hashlib
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qsl, urlunparse, urlencode
from typing import List, Dict, Set, Optional
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

class XSSScanner:
    def __init__(self, target_url: str, config: Dict = None):
        self.target_url = target_url
        self.config = config or {}
        self.session = requests.Session()
        self.vulnerabilities = []
        self.visited_urls = set()
        self.payloads = XSSPayloads()
        self.report_generator = ReportGenerator()
        self.setup_logging()
        self.setup_browser()

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

    def test_form_xss(self, url: str, form: BeautifulSoup) -> None:
        """Test form for XSS vulnerabilities"""
        form_action = form.get('action', '')
        form_method = form.get('method', 'get').lower()
        
        if not form_action:
            form_action = url
            
        form_url = urljoin(url, form_action)
        
        for payload in self.payloads.get_all_payloads():
            try:
                if form_method == 'get':
                    response = self.session.get(form_url, params={payload: payload})
                else:
                    response = self.session.post(form_url, data={payload: payload})
                
                if self.check_xss_success(response, payload):
                    self.report_vulnerability(url, 'form', payload, response)
                    
            except Exception as e:
                self.logger.error(f"Error testing form XSS: {str(e)}")

    def test_input_xss(self, url: str, input_field: BeautifulSoup) -> None:
        """Test input field for XSS vulnerabilities"""
        input_name = input_field.get('name', '')
        if not input_name:
            return
            
        for payload in self.payloads.get_all_payloads():
            try:
                response = self.session.get(url, params={input_name: payload})
                if self.check_xss_success(response, payload):
                    self.report_vulnerability(url, 'input', payload, response)
                    
            except Exception as e:
                self.logger.error(f"Error testing input XSS: {str(e)}")

    def test_link_xss(self, url: str, link: BeautifulSoup) -> None:
        """Test link for XSS vulnerabilities"""
        href = link.get('href', '')
        if not href:
            return
            
        # Skip mailto: links and other non-http(s) protocols
        if href.startswith(('mailto:', 'tel:', 'javascript:', '#')):
            return
            
        for payload in self.payloads.get_all_payloads():
            try:
                test_url = urljoin(url, href)
                response = self.session.get(test_url, params={'test': payload})
                if self.check_xss_success(response, payload):
                    self.report_vulnerability(url, 'link', payload, response)
                    
            except Exception as e:
                self.logger.error(f"Error testing link XSS: {str(e)}")

    def check_xss_success(self, response: requests.Response, payload: str) -> bool:
        """Check if XSS payload was successful"""
        # Normalize the response text and payload for comparison
        response_text = response.text.lower()
        normalized_payload = payload.lower()
        
        # Check for reflected payload (exact match)
        if payload in response.text:
            return True
            
        # Check for split/obfuscated payloads
        if '<scr' in response_text and 'ipt>' in response_text:
            # Look for split script tags
            script_start = response_text.find('<scr')
            script_end = response_text.find('ipt>', script_start)
            if script_start != -1 and script_end != -1:
                # Check if there's any content between the split parts
                between_parts = response_text[script_start+4:script_end]
                if any(c in between_parts for c in ['\n', '\t', '\r', '\x00', '\x0A', '\x0D', '\x09', '\x0C', '\x0B', '\x0E', '\x0F', '\x1A', '\x20']):
                    return True
        
        # Check for common XSS indicators
        xss_indicators = [
            '<script>',
            'alert(',
            'onerror=',
            'onload=',
            'onclick=',
            'onmouseover=',
            'onfocus=',
            'ontoggle=',
            'onstart=',
            'onloadstart=',
            'javascript:',
        ]
        
        for indicator in xss_indicators:
            if indicator in response_text:
                return True
                
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

    def report_vulnerability(self, url: str, vuln_type: str, payload: str, response: requests.Response) -> None:
        """Report a found XSS vulnerability"""
        evidence = self.get_evidence_snippet(response, payload)
        
        vulnerability = {
            'url': url,
            'type': vuln_type,
            'payload': payload,
            'evidence': evidence,
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'response_code': response.status_code,
            'response_headers': dict(response.headers),
        }
        
        self.vulnerabilities.append(vulnerability)
        
        # Log the vulnerability
        self.logger.warning(f"[!] Found XSS vulnerability in {url} ({vuln_type})")
        self.logger.warning(f"Payload: {payload}")
        self.logger.warning(f"Evidence: {evidence}")
        
        # Take screenshot if browser is available
        if self.browser:
            screenshot = self.capture_screenshot(url, payload)
            if screenshot:
                vulnerability['screenshot'] = screenshot

    def generate_report(self) -> None:
        """Generate detailed reports"""
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No XSS vulnerabilities found{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.YELLOW}[*] Generating XSS Scan Reports{Style.RESET_ALL}")
        
        # Generate HTML report
        html_report = self.report_generator.generate_report(self.target_url, self.vulnerabilities)
        print(f"{Fore.GREEN}[+] HTML report saved to: {html_report}{Style.RESET_ALL}")
        
        # Generate JSON report
        json_report = self.report_generator.save_json_report(self.vulnerabilities)
        print(f"{Fore.GREEN}[+] JSON report saved to: {json_report}{Style.RESET_ALL}")

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
