#!/usr/bin/env python3

import os
import json
import base64
from datetime import datetime
from typing import List, Dict
from jinja2 import Template
import logging

class ReportGenerator:
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = output_dir
        self.screenshots_dir = os.path.join(output_dir, "screenshots")
        self._create_directories()
        self.template = self._load_template()

    def _create_directories(self):
        """Create necessary directories for reports and screenshots"""
        os.makedirs(self.output_dir, exist_ok=True)
        os.makedirs(self.screenshots_dir, exist_ok=True)

    def _load_template(self) -> Template:
        """Load HTML report template"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>XSS Vulnerability Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .vulnerability { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
                .vulnerability:hover { box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .header { background: #f5f5f5; padding: 10px; margin: -15px -15px 15px -15px; border-radius: 5px 5px 0 0; }
                .evidence { background: #f8f8f8; padding: 10px; border-radius: 3px; margin: 10px 0; }
                .screenshot { max-width: 100%; margin: 10px 0; border: 1px solid #ddd; }
                .payload { color: #d63384; font-family: monospace; }
                .timestamp { color: #666; font-size: 0.9em; }
                .headers { background: #f8f8f8; padding: 10px; border-radius: 3px; margin: 10px 0; }
                .headers pre { margin: 0; white-space: pre-wrap; }
                .vuln-id { color: #666; font-size: 0.9em; }
                .severity-high { border-left: 5px solid #dc3545; }
                .severity-medium { border-left: 5px solid #ffc107; }
                .severity-low { border-left: 5px solid #0dcaf0; }
            </style>
        </head>
        <body>
            <h1>XSS Vulnerability Report</h1>
            <p>Target URL: {{ target_url }}</p>
            <p>Scan completed at: {{ scan_time }}</p>
            <p>Total vulnerabilities found: {{ vulnerabilities|length }}</p>
            
            {% for vuln in vulnerabilities %}
            <div class="vulnerability severity-{{ vuln.severity|default('medium') }}">
                <div class="header">
                    <h2>XSS Vulnerability #{{ loop.index }}</h2>
                    <div class="vuln-id">ID: {{ vuln.vulnerability_id }}</div>
                    <div class="timestamp">Found at: {{ vuln.timestamp }}</div>
                </div>
                
                <h3>Details</h3>
                <ul>
                    <li><strong>URL:</strong> {{ vuln.url }}</li>
                    <li><strong>Type:</strong> {{ vuln.type }}</li>
                    <li><strong>Status Code:</strong> {{ vuln.status_code }}</li>
                    <li><strong>Response Length:</strong> {{ vuln.response_length }} bytes</li>
                </ul>

                <h3>Payload</h3>
                <div class="evidence">
                    <pre class="payload">{{ vuln.payload }}</pre>
                </div>

                <h3>Evidence</h3>
                <div class="evidence">
                    <pre>{{ vuln.evidence }}</pre>
                </div>

                {% if vuln.screenshot %}
                <h3>Screenshot</h3>
                <img class="screenshot" src="data:image/png;base64,{{ vuln.screenshot }}" alt="XSS Proof of Concept">
                {% endif %}

                <h3>Response Headers</h3>
                <div class="headers">
                    <pre>{{ vuln.headers|tojson(indent=2) }}</pre>
                </div>
            </div>
            {% endfor %}
        </body>
        </html>
        """

    def save_screenshot(self, screenshot_data: bytes, vuln_id: str) -> str:
        """Save screenshot and return the path"""
        filename = f"screenshot_{vuln_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        filepath = os.path.join(self.screenshots_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(screenshot_data)
        return filepath

    def generate_report(self, target_url: str, vulnerabilities: List[Dict]) -> str:
        """Generate HTML report with embedded screenshots"""
        template = self._load_template()
        
        # Process vulnerabilities to include base64 screenshots
        processed_vulns = []
        for vuln in vulnerabilities:
            processed_vuln = vuln.copy()
            if vuln.get('screenshot'):
                try:
                    with open(vuln['screenshot'], 'rb') as f:
                        screenshot_data = base64.b64encode(f.read()).decode('utf-8')
                        processed_vuln['screenshot'] = screenshot_data
                except Exception as e:
                    logging.error(f"Error processing screenshot: {str(e)}")
                    processed_vuln['screenshot'] = None
            processed_vulns.append(processed_vuln)
        
        # Render template
        template = Template(template)
        html_content = template.render(
            target_url=target_url,
            vulnerabilities=processed_vulns,
            scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
        
        # Save report
        report_path = os.path.join(self.output_dir, f'xss_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html')
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return report_path

    def save_json_report(self, vulnerabilities: List[Dict]) -> str:
        """Save vulnerabilities in JSON format"""
        report_path = os.path.join(
            self.output_dir,
            f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(vulnerabilities, f, indent=4)
        return report_path 
