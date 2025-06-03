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
                body { 
                    font-family: Arial, sans-serif; 
                    margin: 20px;
                    line-height: 1.6;
                    color: #333;
                }
                .vulnerability { 
                    border: 1px solid #ddd; 
                    margin: 20px 0; 
                    padding: 20px; 
                    border-radius: 8px;
                    background: #fff;
                }
                .vulnerability:hover { 
                    box-shadow: 0 0 15px rgba(0,0,0,0.1); 
                }
                .header { 
                    background: #f8f9fa; 
                    padding: 15px; 
                    margin: -20px -20px 20px -20px; 
                    border-radius: 8px 8px 0 0;
                    border-bottom: 1px solid #ddd;
                }
                .evidence { 
                    background: #f8f9fa; 
                    padding: 15px; 
                    border-radius: 6px; 
                    margin: 15px 0;
                    font-family: monospace;
                    white-space: pre-wrap;
                    word-break: break-all;
                }
                .screenshot { 
                    max-width: 100%; 
                    margin: 15px 0; 
                    border: 1px solid #ddd;
                    border-radius: 4px;
                }
                .payload { 
                    color: #d63384; 
                    font-family: monospace;
                    background: #f8f9fa;
                    padding: 10px;
                    border-radius: 4px;
                    margin: 10px 0;
                }
                .timestamp { 
                    color: #666; 
                    font-size: 0.9em;
                    margin-top: 5px;
                }
                .headers { 
                    background: #f8f9fa; 
                    padding: 15px; 
                    border-radius: 6px; 
                    margin: 15px 0;
                    font-family: monospace;
                }
                .headers pre { 
                    margin: 0; 
                    white-space: pre-wrap;
                    word-break: break-all;
                }
                .vuln-id { 
                    color: #666; 
                    font-size: 0.9em;
                    font-family: monospace;
                }
                .severity-high { 
                    border-left: 5px solid #dc3545; 
                }
                .severity-medium { 
                    border-left: 5px solid #ffc107; 
                }
                .severity-low { 
                    border-left: 5px solid #0dcaf0; 
                }
                .summary {
                    background: #f8f9fa;
                    padding: 20px;
                    border-radius: 8px;
                    margin-bottom: 30px;
                }
                .summary-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-top: 15px;
                }
                .summary-item {
                    background: white;
                    padding: 15px;
                    border-radius: 6px;
                    text-align: center;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                }
                .summary-item h3 {
                    margin: 0;
                    color: #666;
                    font-size: 0.9em;
                }
                .summary-item p {
                    margin: 10px 0 0 0;
                    font-size: 1.5em;
                    font-weight: bold;
                    color: #333;
                }
                .parameter-info {
                    background: #e9ecef;
                    padding: 10px;
                    border-radius: 4px;
                    margin: 10px 0;
                    font-family: monospace;
                }
                .context {
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 6px;
                    margin: 15px 0;
                    font-family: monospace;
                    white-space: pre-wrap;
                    word-break: break-all;
                }
            </style>
        </head>
        <body>
            <h1>XSS Vulnerability Report</h1>
            
            <div class="summary">
                <h2>Scan Summary</h2>
                <div class="summary-grid">
                    <div class="summary-item">
                        <h3>Target URL</h3>
                        <p>{{ target_url }}</p>
                    </div>
                    <div class="summary-item">
                        <h3>Scan Time</h3>
                        <p>{{ scan_time }}</p>
                    </div>
                    <div class="summary-item">
                        <h3>Total Vulnerabilities</h3>
                        <p>{{ vulnerabilities|length }}</p>
                    </div>
                    <div class="summary-item">
                        <h3>High Severity</h3>
                        <p>{{ vulnerabilities|selectattr('severity', 'equalto', 'high')|list|length }}</p>
                    </div>
                </div>
            </div>
            
            {% for vuln in vulnerabilities %}
            <div class="vulnerability severity-{{ vuln.severity|default('medium') }}">
                <div class="header">
                    <h2>XSS Vulnerability #{{ loop.index }}</h2>
                    <div class="vuln-id">ID: {{ vuln.vulnerability_id }}</div>
                    <div class="timestamp">Found at: {{ vuln.timestamp }}</div>
                </div>
                
                <h3>Vulnerability Details</h3>
                <ul>
                    <li><strong>URL:</strong> {{ vuln.url }}</li>
                    <li><strong>Type:</strong> {{ vuln.type }}</li>
                    <li><strong>Parameter:</strong> <span class="parameter-info">{{ vuln.parameter }}</span></li>
                    <li><strong>Severity:</strong> {{ vuln.severity|title }}</li>
                    <li><strong>Status Code:</strong> {{ vuln.status_code }}</li>
                    <li><strong>Response Length:</strong> {{ vuln.response_length }} bytes</li>
                </ul>

                <h3>Payload</h3>
                <div class="payload">{{ vuln.payload }}</div>

                <h3>Context</h3>
                <div class="context">{{ vuln.context }}</div>

                <h3>Evidence</h3>
                <div class="evidence">{{ vuln.evidence }}</div>

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

    def save_json_report(self, vulnerabilities: List[Dict]) -> str:
        """Save vulnerabilities to a JSON file"""
        try:
            # Process vulnerabilities to handle binary data
            processed_vulns = []
            for vuln in vulnerabilities:
                processed_vuln = vuln._asdict() if hasattr(vuln, '_asdict') else vuln
                # Convert screenshot to base64 if present
                if processed_vuln.get('screenshot'):
                    try:
                        if isinstance(processed_vuln['screenshot'], bytes):
                            processed_vuln['screenshot'] = base64.b64encode(processed_vuln['screenshot']).decode('utf-8')
                    except Exception as e:
                        logging.error(f"Error processing screenshot: {str(e)}")
                        processed_vuln['screenshot'] = None
                processed_vulns.append(processed_vuln)
            
            # Save to JSON file
            report_path = os.path.join(self.output_dir, f'xss_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(processed_vulns, f, indent=4)
            return report_path
        except Exception as e:
            logging.error(f"Error saving JSON report: {str(e)}")
            return None

    def generate_report(self, target_url: str, vulnerabilities: List[Dict]) -> str:
        """Generate HTML report with embedded screenshots"""
        template = self._load_template()
        
        # Process vulnerabilities to include base64 screenshots
        processed_vulns = []
        for vuln in vulnerabilities:
            processed_vuln = vuln._asdict() if hasattr(vuln, '_asdict') else vuln
            if processed_vuln.get('screenshot'):
                try:
                    if isinstance(processed_vuln['screenshot'], bytes):
                        processed_vuln['screenshot'] = base64.b64encode(processed_vuln['screenshot']).decode('utf-8')
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
