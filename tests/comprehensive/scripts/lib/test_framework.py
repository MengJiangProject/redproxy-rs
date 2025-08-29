#!/usr/bin/env python3
"""
Reusable Test Framework for RedProxy Comprehensive Tests
Provides patterns for selective test execution, timeout handling, and argument parsing
Integrates with existing TestReporter and TestUtils infrastructure
"""

import argparse
import asyncio
import os
import sys
import time
from typing import Dict, List, Tuple, Callable, Optional

from test_utils import TestLogger, TestEnvironment, setup_test_environment
from test_reporter import TestReporter, TestResult, TestSuite


class SelectiveTestRunner:
    """Test runner with selective execution and timeout support"""
    
    def __init__(self, suite_name: str, description: str):
        self.suite_name = suite_name
        self.description = description
        self.available_tests: Dict[str, Tuple[str, Callable]] = {}
        
    def register_test(self, test_id: str, display_name: str, test_func: Callable):
        """Register a test function"""
        self.available_tests[test_id] = (display_name, test_func)
        
    def get_test_ids(self) -> List[str]:
        """Get list of available test IDs"""
        return list(self.available_tests.keys())
        
    def get_test_descriptions(self) -> List[Tuple[str, str]]:
        """Get list of (test_id, description) tuples"""
        return [(test_id, display_name) for test_id, (display_name, _) in self.available_tests.items()]
        
    def validate_test_selection(self, selected_tests: List[str]) -> Tuple[bool, List[str]]:
        """Validate selected test names"""
        if not selected_tests:
            return True, []
            
        invalid_tests = [t for t in selected_tests if t not in self.available_tests]
        return len(invalid_tests) == 0, invalid_tests
        
    async def run_tests(self, 
                       selected_tests: Optional[List[str]] = None, 
                       timeout_per_test: float = 60.0,
                       setup_env: bool = True) -> bool:
        """Run tests with existing infrastructure integration"""
        
        # Set up environment and reporter (using existing infrastructure)
        if setup_env:
            env = setup_test_environment()
        
        reporter = TestReporter(output_dir="/reports")
        reporter.set_environment({
            "test_type": self.suite_name.lower().replace(" ", "_"),
            "redproxy_version": os.environ.get("REDPROXY_VERSION", "unknown")
        })
        
        suite = reporter.create_suite(self.suite_name)
        
        # Validate selection
        is_valid, invalid_tests = self.validate_test_selection(selected_tests or [])
        if not is_valid:
            TestLogger.error(f"Invalid test names: {invalid_tests}")
            TestLogger.error(f"Available tests: {self.get_test_ids()}")
            return False
            
        # Determine tests to run
        if selected_tests:
            tests_to_run = [(test_id, self.available_tests[test_id]) for test_id in selected_tests]
            TestLogger.info(f"=== {self.suite_name} ({', '.join(selected_tests)}) ===")
        else:
            tests_to_run = list(self.available_tests.items())
            TestLogger.info(f"=== {self.suite_name} ===")
            
        TestLogger.info(f"Running {len(tests_to_run)} test(s) with {timeout_per_test}s timeout each...")
        
        # Run tests with timeout protection and proper reporting
        for i, (test_id, (display_name, test_func)) in enumerate(tests_to_run, 1):
            TestLogger.info(f"Running {display_name} ({i}/{len(tests_to_run)})...")
            start_time = time.time()
            
            try:
                # Run test with timeout
                result = await asyncio.wait_for(test_func(), timeout=timeout_per_test)
                duration = time.time() - start_time
                
                # Create test result using existing infrastructure
                test_result = TestResult(
                    name=display_name,
                    status="passed" if result else "failed",
                    duration=duration
                )
                suite.tests.append(test_result)
                
                if result:
                    TestLogger.info(f"✅ {display_name} passed in {duration:.1f}s")
                else:
                    TestLogger.error(f"❌ {display_name} failed in {duration:.1f}s")
                
            except asyncio.TimeoutError:
                duration = time.time() - start_time
                TestLogger.error(f"⏰ {display_name} timed out after {duration:.1f}s")
                
                test_result = TestResult(
                    name=display_name,
                    status="failed",
                    duration=duration,
                    error_message=f"Test timed out after {timeout_per_test}s"
                )
                suite.tests.append(test_result)
                
            except Exception as e:
                duration = time.time() - start_time
                TestLogger.error(f"💥 {display_name} failed with exception after {duration:.1f}s: {e}")
                
                test_result = TestResult(
                    name=display_name,
                    status="failed",
                    duration=duration,
                    error_message=str(e)
                )
                suite.tests.append(test_result)
            
            print()  # Blank line between tests
        
        # Generate reports using existing infrastructure
        reporter.finalize_suite(suite)
        json_path = reporter.save_json_report(f"{self.suite_name.lower().replace(' ', '_')}_report.json")
        html_path = reporter.save_html_report(f"{self.suite_name.lower().replace(' ', '_')}_report.html")
        
        # Summary using existing infrastructure
        passed = suite.passed_tests
        total = suite.total_tests
        
        TestLogger.info("=" * 60)
        TestLogger.info(f"{self.suite_name} Results: {passed}/{total} tests passed")
        TestLogger.info(f"Reports saved: {json_path}, {html_path}")
        
        if passed == total:
            TestLogger.info(f"🎉 All {self.suite_name.lower()} PASSED!")
            return True
        else:
            TestLogger.error(f"❌ {total - passed} test(s) FAILED")
            return False


class TestArgumentParser:
    """Standardized argument parser for test scripts"""
    
    def __init__(self, script_name: str, description: str, test_runner: SelectiveTestRunner):
        self.script_name = script_name
        self.description = description
        self.test_runner = test_runner
        
    def create_parser(self) -> argparse.ArgumentParser:
        """Create standardized argument parser"""
        # Build epilog with available tests
        test_descriptions = self.test_runner.get_test_descriptions()
        epilog_lines = [
            "Available test suites:",
            *[f"  {test_id:<12} - {desc}" for test_id, desc in test_descriptions],
            "",
            "Examples:",
            f"  {self.script_name}                           # Run all tests",
            f"  {self.script_name} --tests basic errors     # Run only specific tests",
            f"  {self.script_name} --list                    # List available tests",
            f"  {self.script_name} --timeout 120            # Set timeout per test",
        ]
        
        parser = argparse.ArgumentParser(
            description=self.description,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="\n".join(epilog_lines)
        )
        
        parser.add_argument(
            "--tests", "-t",
            nargs="+",
            metavar="TEST",
            help="Run only specified test suites (space-separated)"
        )
        
        parser.add_argument(
            "--list", "-l",
            action="store_true",
            help="List available test suites and exit"
        )
        
        parser.add_argument(
            "--timeout",
            type=float,
            default=60.0,
            metavar="SECONDS",
            help="Timeout per test in seconds (default: 60)"
        )
        
        return parser
        
    def handle_list_command(self):
        """Handle --list command"""
        print(f"Available {self.test_runner.suite_name.lower()} test suites:")
        test_descriptions = self.test_runner.get_test_descriptions()
        
        for test_id, description in test_descriptions:
            print(f"  {test_id:<12} - {description}")
        
        print(f"\nUsage: {self.script_name} --tests basic errors")
        sys.exit(0)


async def run_test_script(script_name: str, description: str, test_runner: SelectiveTestRunner):
    """Main entry point for test scripts with existing infrastructure integration"""
    parser_helper = TestArgumentParser(script_name, description, test_runner)
    parser = parser_helper.create_parser()
    args = parser.parse_args()
    
    # Handle --list option
    if args.list:
        parser_helper.handle_list_command()
    
    try:
        success = await test_runner.run_tests(
            selected_tests=args.tests,
            timeout_per_test=args.timeout
        )
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        TestLogger.warn("Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        TestLogger.error(f"Test execution failed: {e}")
        sys.exit(1)


# Utility functions for common test patterns
async def run_test_with_timeout(test_func: Callable, timeout: float = 10.0, test_name: str = "Test") -> bool:
    """Run a single test function with timeout protection"""
    try:
        result = await asyncio.wait_for(test_func(), timeout=timeout)
        return result
    except asyncio.TimeoutError:
        TestLogger.error(f"⏰ {test_name} timed out after {timeout}s")
        return False
    except Exception as e:
        TestLogger.error(f"💥 {test_name} failed: {e}")
        return False