#!/usr/bin/env python3

import os
import json
import base64
from datetime import datetime
from typing import List, Dict
from jinja2 import Template

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
        template_str = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>XSS Vulnerability Report</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 20px;
                    border-radius: 5px;
                    box-shadow: 0 0 10px rgba(0,0,0,0.1);
                }
                .header {
                    text-align: center;
                    margin-bottom: 30px;
                    padding-bottom: 20px;
                    border-bottom: 2px solid #eee;
                }
                .vulnerability {
                    margin-bottom: 30px;
                    padding: 20px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                    background-color: #fff;
                }
                .vulnerability h3 {
                    margin-top: 0;
                    color: #d32f2f;
                }
                .details {
                    margin: 15px 0;
                }
                .details p {
                    margin: 5px 0;
                }
                .screenshot {
                    max-width: 100%;
                    margin: 15px 0;
                    border: 1px solid #ddd;
                }
                .evidence {
                    background-color: #f8f9fa;
                    padding: 15px;
                    border-radius: 5px;
                    font-family: monospace;
                    white-space: pre-wrap;
                    word-break: break-all;
                }
                .timestamp {
                    color: #666;
                    font-size: 0.9em;
                }
                .summary {
                    margin-bottom: 30px;
                    padding: 20px;
                    background-color: #e3f2fd;
                    border-radius: 5px;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>XSS Vulnerability Report</h1>
                    <p class="timestamp">Generated on: {{ timestamp }}</p>
                </div>
                
                <div class="summary">
                    <h2>Scan Summary</h2>
                    <p>Target URL: {{ target_url }}</p>
                    <p>Total Vulnerabilities Found: {{ vulnerabilities|length }}</p>
                </div>

                {% for vuln in vulnerabilities %}
                <div class="vulnerability">
                    <h3>Vulnerability #{{ loop.index }}</h3>
                    <div class="details">
                        <p><strong>URL:</strong> {{ vuln.url }}</p>
                        <p><strong>Type:</strong> {{ vuln.type }}</p>
                        <p><strong>Payload:</strong> <code>{{ vuln.payload }}</code></p>
                        <p><strong>Status Code:</strong> {{ vuln.status_code }}</p>
                        
                        {% if vuln.screenshot %}
                        <h4>Screenshot Evidence:</h4>
                        <img class="screenshot" src="data:image/png;base64,{{ vuln.screenshot }}" alt="XSS Screenshot">
                        {% endif %}
                        
                        {% if vuln.evidence %}
                        <h4>Response Evidence:</h4>
                        <div class="evidence">{{ vuln.evidence }}</div>
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
            </div>
        </body>
        </html>
        """
        return Template(template_str)

    def save_screenshot(self, screenshot_data: bytes, vuln_id: str) -> str:
        """Save screenshot and return the path"""
        filename = f"screenshot_{vuln_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        filepath = os.path.join(self.screenshots_dir, filename)
        with open(filepath, 'wb') as f:
            f.write(screenshot_data)
        return filepath

    def generate_report(self, target_url: str, vulnerabilities: List[Dict]) -> str:
        """Generate HTML report with screenshots"""
        # Process vulnerabilities to include screenshots
        for vuln in vulnerabilities:
            if 'screenshot' in vuln and vuln['screenshot']:
                # Convert screenshot to base64 for embedding
                with open(vuln['screenshot'], 'rb') as f:
                    screenshot_data = f.read()
                vuln['screenshot'] = base64.b64encode(screenshot_data).decode('utf-8')

        # Generate report
        report_html = self.template.render(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            target_url=target_url,
            vulnerabilities=vulnerabilities
        )

        # Save report
        report_path = os.path.join(
            self.output_dir,
            f"xss_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(report_html)

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
