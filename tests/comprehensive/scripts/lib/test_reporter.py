#!/usr/bin/env python3
"""
Test reporter for RedProxy comprehensive tests
Generates JSON and HTML test reports
"""

import json
import time
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from pathlib import Path


@dataclass
class TestResult:
    """Individual test result"""
    name: str
    status: str  # "passed", "failed", "skipped"
    duration: float = 0.0
    error_message: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestSuite:
    """Test suite results"""
    name: str
    tests: List[TestResult] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    
    @property
    def duration(self) -> float:
        return self.end_time - self.start_time if self.end_time > 0 else 0.0
    
    @property
    def total_tests(self) -> int:
        return len(self.tests)
    
    @property
    def passed_tests(self) -> int:
        return sum(1 for test in self.tests if test.status == "passed")
    
    @property
    def failed_tests(self) -> int:
        return sum(1 for test in self.tests if test.status == "failed")
    
    @property
    def skipped_tests(self) -> int:
        return sum(1 for test in self.tests if test.status == "skipped")
    
    @property
    def success_rate(self) -> float:
        return self.passed_tests / self.total_tests if self.total_tests > 0 else 0.0


@dataclass
class TestReport:
    """Complete test report"""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    environment: Dict[str, str] = field(default_factory=dict)
    suites: List[TestSuite] = field(default_factory=list)
    
    @property
    def total_tests(self) -> int:
        return sum(suite.total_tests for suite in self.suites)
    
    @property
    def total_passed(self) -> int:
        return sum(suite.passed_tests for suite in self.suites)
    
    @property
    def total_failed(self) -> int:
        return sum(suite.failed_tests for suite in self.suites)
    
    @property
    def total_skipped(self) -> int:
        return sum(suite.skipped_tests for suite in self.suites)
    
    @property
    def overall_success_rate(self) -> float:
        return self.total_passed / self.total_tests if self.total_tests > 0 else 0.0
    
    @property
    def total_duration(self) -> float:
        return sum(suite.duration for suite in self.suites)


class TestReporter:
    """Test reporter for generating JSON and HTML reports"""
    
    def __init__(self, output_dir: Path = Path("reports")):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.report = TestReport()
        
    def set_environment(self, env_info: Dict[str, str]):
        """Set environment information"""
        self.report.environment = env_info
        
    def create_suite(self, name: str) -> TestSuite:
        """Create and add a new test suite"""
        suite = TestSuite(name=name)
        self.report.suites.append(suite)
        return suite
        
    def finalize_suite(self, suite: TestSuite):
        """Finalize a test suite (set end time)"""
        suite.end_time = time.time()
        
    def save_json_report(self, filename: str = "test_report.json"):
        """Save test report as JSON"""
        json_path = self.output_dir / filename
        
        # Convert to dict and handle dataclass serialization
        report_dict = asdict(self.report)
        
        with open(json_path, 'w') as f:
            json.dump(report_dict, f, indent=2, default=str)
            
        return json_path
        
    def save_html_report(self, filename: str = "test_report.html"):
        """Save test report as HTML"""
        html_path = self.output_dir / filename
        
        html_content = self._generate_html_report()
        
        with open(html_path, 'w') as f:
            f.write(html_content)
            
        return html_path
        
    def _generate_html_report(self) -> str:
        """Generate HTML report content"""
        
        # Status colors
        status_colors = {
            "passed": "#28a745",
            "failed": "#dc3545", 
            "skipped": "#ffc107"
        }
        
        # Calculate overall statistics
        overall_status = "passed" if self.report.overall_success_rate >= 0.8 else "failed"
        overall_color = status_colors[overall_status]
        
        # Generate suite rows
        suite_rows = ""
        for suite in self.report.suites:
            suite_status = "passed" if suite.success_rate >= 0.8 else "failed"
            suite_color = status_colors[suite_status]
            
            suite_rows += f"""
                <tr>
                    <td>{suite.name}</td>
                    <td>{suite.total_tests}</td>
                    <td style="color: {status_colors['passed']}">{suite.passed_tests}</td>
                    <td style="color: {status_colors['failed']}">{suite.failed_tests}</td>
                    <td style="color: {status_colors['skipped']}">{suite.skipped_tests}</td>
                    <td style="color: {suite_color}; font-weight: bold">{suite.success_rate:.1%}</td>
                    <td>{suite.duration:.2f}s</td>
                </tr>
            """
            
        # Generate detailed test results
        detailed_results = ""
        for suite in self.report.suites:
            detailed_results += f"""
                <h3>{suite.name} Tests</h3>
                <table class="table">
                    <thead>
                        <tr>
                            <th>Test Name</th>
                            <th>Status</th>
                            <th>Duration</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
            """
            
            for test in suite.tests:
                test_color = status_colors.get(test.status, "#6c757d")
                error_details = f"<small style='color: {status_colors['failed']}'>{test.error_message}</small>" if test.error_message else ""
                test_details = json.dumps(test.details, indent=2) if test.details else ""
                
                detailed_results += f"""
                    <tr>
                        <td>{test.name}</td>
                        <td style="color: {test_color}; font-weight: bold">{test.status.upper()}</td>
                        <td>{test.duration:.2f}s</td>
                        <td>
                            {error_details}
                            {f"<pre style='font-size: 0.8em; margin-top: 5px'>{test_details}</pre>" if test_details else ""}
                        </td>
                    </tr>
                """
                
            detailed_results += """
                    </tbody>
                </table>
            """
        
        return f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>RedProxy Comprehensive Test Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; }}
        .header {{ text-align: center; margin-bottom: 40px; }}
        .summary {{ background: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 30px; }}
        .table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        .table th, .table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        .table th {{ background: #f8f9fa; font-weight: 600; }}
        .status-badge {{ padding: 4px 8px; border-radius: 4px; color: white; font-weight: bold; }}
        .passed {{ background-color: {status_colors['passed']}; }}
        .failed {{ background-color: {status_colors['failed']}; }}
        .skipped {{ background-color: {status_colors['skipped']}; }}
        pre {{ background: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; }}
        .metric {{ display: inline-block; margin: 0 20px; }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: {overall_color}; }}
        .metric-label {{ font-size: 0.9em; color: #6c757d; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>RedProxy Comprehensive Test Report</h1>
        <p>Generated: {self.report.timestamp}</p>
    </div>
    
    <div class="summary">
        <h2>Overall Results</h2>
        <div style="text-align: center;">
            <div class="metric">
                <div class="metric-value">{self.report.overall_success_rate:.1%}</div>
                <div class="metric-label">Success Rate</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #007bff">{self.report.total_tests}</div>
                <div class="metric-label">Total Tests</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: {status_colors['passed']}">{self.report.total_passed}</div>
                <div class="metric-label">Passed</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: {status_colors['failed']}">{self.report.total_failed}</div>
                <div class="metric-label">Failed</div>
            </div>
            <div class="metric">
                <div class="metric-value" style="color: #6c757d">{self.report.total_duration:.2f}s</div>
                <div class="metric-label">Duration</div>
            </div>
        </div>
    </div>
    
    <h2>Test Suites Summary</h2>
    <table class="table">
        <thead>
            <tr>
                <th>Suite</th>
                <th>Total</th>
                <th>Passed</th>
                <th>Failed</th>
                <th>Skipped</th>
                <th>Success Rate</th>
                <th>Duration</th>
            </tr>
        </thead>
        <tbody>
            {suite_rows}
        </tbody>
    </table>
    
    <h2>Detailed Results</h2>
    {detailed_results}
    
    {"<h2>Environment</h2><pre>" + json.dumps(self.report.environment, indent=2) + "</pre>" if self.report.environment else ""}
</body>
</html>
        """.strip()