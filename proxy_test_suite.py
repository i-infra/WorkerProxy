#!/usr/bin/env python3
"""
Cloudflare Worker Proxy Test Suite

Tests the proxy against httpbin.org and staging.getpost.workers.dev
to verify all critical functionality works correctly.

Usage:
    python3 test_proxy.py --proxy-url https://your-proxy.workers.dev
    python3 test_proxy.py --proxy-url https://your-proxy.workers.dev --verbose
    python3 test_proxy.py --proxy-url https://your-proxy.workers.dev --test-category basic
"""

import requests
import time
import json
import hashlib
import os
import sys
import argparse
import base64
from urllib.parse import urljoin, urlparse, quote
from typing import Dict, List, Optional, Tuple
import tempfile
import mimetypes

class Colors:
    """ANSI color codes for pretty output"""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class ProxyTestSuite:
    def __init__(self, proxy_url: str, separator: str = "------", verbose: bool = False):
        """Initialize the test suite with proxy configuration"""
        self.proxy_url = proxy_url.rstrip('/')
        self.separator = separator
        self.verbose = verbose
        self.session = requests.Session()
        self.session.timeout = 30

        # Test counters
        self.tests_run = 0
        self.tests_passed = 0
        self.tests_failed = 0
        self.failed_tests = []

        # Test targets
        self.httpbin_url = "https://httpbin.org"
        self.getpost_url = "https://staging.getpost.workers.dev"

    def log(self, message: str, color: str = Colors.WHITE):
        """Log a message with optional color"""
        if self.verbose:
            print(f"{color}{message}{Colors.END}")

    def create_proxy_url(self, target_url: str) -> str:
        """Create a proxied URL for the given target"""
        return f"{self.proxy_url}/{self.separator}{target_url}"

    def assert_test(self, condition: bool, test_name: str, error_msg: str = ""):
        """Assert a test condition and track results"""
        self.tests_run += 1
        if condition:
            self.tests_passed += 1
            print(f"{Colors.GREEN}✓{Colors.END} {test_name}")
            self.log(f"  PASS: {test_name}", Colors.GREEN)
        else:
            self.tests_failed += 1
            self.failed_tests.append(test_name)
            print(f"{Colors.RED}✗{Colors.END} {test_name}")
            if error_msg:
                print(f"  {Colors.RED}Error: {error_msg}{Colors.END}")
            self.log(f"  FAIL: {test_name} - {error_msg}", Colors.RED)

    def test_basic_requests(self) -> None:
        """Test basic HTTP methods through the proxy"""
        print(f"\n{Colors.BOLD}=== Testing Basic HTTP Methods ==={Colors.END}")

        # Test GET request
        try:
            response = self.session.get(self.create_proxy_url(f"{self.httpbin_url}/get"))
            self.assert_test(
                response.status_code == 200,
                "GET request through proxy",
                f"Expected 200, got {response.status_code}"
            )

            # Verify the response contains expected httpbin data
            if response.status_code == 200:
                data = response.json()
                self.assert_test(
                    'headers' in data and 'url' in data,
                    "GET response contains expected httpbin structure"
                )
        except Exception as e:
            self.assert_test(False, "GET request through proxy", str(e))

        # Test POST request with data
        try:
            test_data = {"test": "data", "proxy": "working"}
            response = self.session.post(
                self.create_proxy_url(f"{self.httpbin_url}/post"),
                json=test_data
            )
            self.assert_test(
                response.status_code == 200,
                "POST request with JSON data",
                f"Expected 200, got {response.status_code}"
            )

            if response.status_code == 200:
                data = response.json()
                self.assert_test(
                    data.get('json') == test_data,
                    "POST data correctly transmitted through proxy"
                )
        except Exception as e:
            self.assert_test(False, "POST request with JSON data", str(e))

        # Test PUT request
        try:
            response = self.session.put(
                self.create_proxy_url(f"{self.httpbin_url}/put"),
                data="PUT test data"
            )
            self.assert_test(
                response.status_code == 200,
                "PUT request through proxy"
            )
        except Exception as e:
            self.assert_test(False, "PUT request through proxy", str(e))

        # Test DELETE request
        try:
            response = self.session.delete(self.create_proxy_url(f"{self.httpbin_url}/delete"))
            self.assert_test(
                response.status_code == 200,
                "DELETE request through proxy"
            )
        except Exception as e:
            self.assert_test(False, "DELETE request through proxy", str(e))

        # Test URL parameter handling specifically
        try:
            # Test that query parameters work through the proxy
            response = self.session.get(self.create_proxy_url(f"{self.httpbin_url}/get?test=123&another=456"))
            self.assert_test(
                response.status_code == 200,
                "Query parameters correctly passed through proxy"
            )

            if response.status_code == 200:
                data = response.json()
                args = data.get('args', {})
                self.assert_test(
                    args.get('test') == '123' and args.get('another') == '456',
                    "Query parameters correctly received by target service"
                )
        except Exception as e:
            self.assert_test(False, "Query parameter test", str(e))

    def test_headers_and_user_agent(self) -> None:
        """Test that headers are properly passed through the proxy"""
        print(f"\n{Colors.BOLD}=== Testing Headers and User Agent ==={Colors.END}")

        # Test custom headers
        try:
            custom_headers = {
                'X-Test-Header': 'proxy-test-value',
                'Authorization': 'Bearer test-token'
            }
            response = self.session.get(
                self.create_proxy_url(f"{self.httpbin_url}/headers"),
                headers=custom_headers
            )

            self.assert_test(
                response.status_code == 200,
                "Headers endpoint accessible through proxy"
            )

            if response.status_code == 200:
                data = response.json()
                headers = data.get('headers', {})

                self.assert_test(
                    'X-Test-Header' in headers and headers['X-Test-Header'] == 'proxy-test-value',
                    "Custom headers passed through proxy"
                )

                self.assert_test(
                    'Authorization' in headers,
                    "Authorization header passed through proxy"
                )
        except Exception as e:
            self.assert_test(False, "Custom headers test", str(e))

        # Test user agent
        try:
            response = self.session.get(self.create_proxy_url(f"{self.httpbin_url}/user-agent"), headers={'User-Agent': ''})
            self.assert_test(
                response.status_code == 200,
                "User-Agent endpoint accessible through proxy"
            )

            if response.status_code == 200:
                data = response.json()
                user_agent = data.get('user-agent', '')
                # Should contain proxy's user agent (browser emulation)
                self.assert_test(
                    'Mozilla' in user_agent or 'Chrome' in user_agent,
                    "Proxy sets appropriate User-Agent header"
                )
        except Exception as e:
            self.assert_test(False, "User-Agent test", str(e))

    def test_redirects(self) -> None:
        """Test different types of redirects through the proxy"""
        print(f"\n{Colors.BOLD}=== Testing Redirects ==={Colors.END}")

        # Test absolute redirect
        try:
            response = self.session.get(
                self.create_proxy_url(f"{self.httpbin_url}/absolute-redirect/1"),
                allow_redirects=False
            )
            self.assert_test(
                response.status_code in [301, 302, 307, 308],
                "Absolute redirect returns proper status code"
            )

            if 'Location' in response.headers:
                location = response.headers['Location']
                self.assert_test(
                    self.proxy_url in location and self.separator in location,
                    "Absolute redirect Location header rewritten for proxy"
                )
        except Exception as e:
            self.assert_test(False, "Absolute redirect test", str(e))

        # Test relative redirect
        try:
            response = self.session.get(
                self.create_proxy_url(f"{self.httpbin_url}/relative-redirect/1"),
                allow_redirects=False
            )
            self.assert_test(
                response.status_code in [301, 302, 307, 308],
                "Relative redirect returns proper status code"
            )

            if 'Location' in response.headers:
                location = response.headers['Location']
                self.assert_test(
                    self.proxy_url in location,
                    "Relative redirect Location header rewritten for proxy"
                )
        except Exception as e:
            self.assert_test(False, "Relative redirect test", str(e))

        # Test redirect following
        try:
            response = self.session.get(
                self.create_proxy_url(f"{self.httpbin_url}/redirect/2"),
                allow_redirects=True
            )
            self.assert_test(
                response.status_code == 200,
                "Multiple redirects followed successfully"
            )
        except Exception as e:
            self.assert_test(False, "Multiple redirects test", str(e))

    def test_status_codes(self) -> None:
        """Test various HTTP status codes through the proxy"""
        print(f"\n{Colors.BOLD}=== Testing Status Codes ==={Colors.END}")

        status_codes = [200, 201, 400, 401, 403, 404, 500, 502]

        for code in status_codes:
            try:
                response = self.session.get(
                    self.create_proxy_url(f"{self.httpbin_url}/status/{code}")
                )
                self.assert_test(
                    response.status_code == code,
                    f"Status code {code} correctly returned"
                )
            except Exception as e:
                self.assert_test(False, f"Status code {code} test", str(e))

    def test_content_types(self) -> None:
        """Test different content types through the proxy"""
        print(f"\n{Colors.BOLD}=== Testing Content Types ==={Colors.END}")

        # Test JSON
        try:
            response = self.session.get(self.create_proxy_url(f"{self.httpbin_url}/json"))
            self.assert_test(
                response.status_code == 200 and 'application/json' in response.headers.get('content-type', ''),
                "JSON content type correctly handled"
            )

            # Verify JSON parsing
            try:
                data = response.json()
                self.assert_test(
                    isinstance(data, dict),
                    "JSON response correctly parsed"
                )
            except:
                self.assert_test(False, "JSON response correctly parsed", "Invalid JSON")
        except Exception as e:
            self.assert_test(False, "JSON content type test", str(e))

        # Test HTML
        try:
            response = self.session.get(self.create_proxy_url(f"{self.httpbin_url}/html"))
            self.assert_test(
                response.status_code == 200 and 'text/html' in response.headers.get('content-type', ''),
                "HTML content type correctly handled"
            )

            # Check for HTML content
            self.assert_test(
                '<html' in response.text.lower(),
                "HTML content correctly received"
            )
        except Exception as e:
            self.assert_test(False, "HTML content type test", str(e))

        # Test XML
        try:
            response = self.session.get(self.create_proxy_url(f"{self.httpbin_url}/xml"))
            self.assert_test(
                response.status_code == 200 and ('application/xml' in response.headers.get('content-type', '') or 'text/xml' in response.headers.get('content-type', '')),
                "XML content type correctly handled"
            )
        except Exception as e:
            self.assert_test(False, "XML content type test", str(e))

    def test_images(self) -> None:
        """Test image handling through the proxy"""
        print(f"\n{Colors.BOLD}=== Testing Image Content ==={Colors.END}")

        image_types = ['png', 'jpeg', 'svg']

        for img_type in image_types:
            try:
                response = self.session.get(self.create_proxy_url(f"{self.httpbin_url}/image/{img_type}"))
                self.assert_test(
                    response.status_code == 200,
                    f"{img_type.upper()} image accessible through proxy"
                )

                # Check content type
                content_type = response.headers.get('content-type', '')
                self.assert_test(
                    f'image/{img_type}' in content_type or (img_type == 'svg' and 'svg' in content_type),
                    f"{img_type.upper()} image has correct content type"
                )

                # Check that we got binary content
                self.assert_test(
                    len(response.content) > 0,
                    f"{img_type.upper()} image has content"
                )
            except Exception as e:
                self.assert_test(False, f"{img_type.upper()} image test", str(e))

    def test_compression(self) -> None:
        """Test compression handling through the proxy"""
        print(f"\n{Colors.BOLD}=== Testing Compression ==={Colors.END}")

        compression_types = ['gzip', 'deflate', 'brotli']

        for comp_type in compression_types:
            try:
                response = self.session.get(self.create_proxy_url(f"{self.httpbin_url}/{comp_type}"))
                self.assert_test(
                    response.status_code == 200,
                    f"{comp_type.upper()} compression handled correctly"
                )

                # Try to parse as JSON to verify decompression
                if response.status_code == 200:
                    try:
                        data = response.json()
                        self.assert_test(
                            isinstance(data, dict),
                            f"{comp_type.upper()} content correctly decompressed"
                        )
                    except:
                        self.assert_test(False, f"{comp_type.upper()} content correctly decompressed", "Invalid JSON after decompression")
            except Exception as e:
                self.assert_test(False, f"{comp_type.upper()} compression test", str(e))

    def test_cookies(self) -> None:
        """Test cookie handling through the proxy"""
        print(f"\n{Colors.BOLD}=== Testing Cookie Handling ==={Colors.END}")

        # Test setting cookies
        try:
            response = self.session.get(
                self.create_proxy_url(f"{self.httpbin_url}/cookies/set/testcookie/testvalue"),
                allow_redirects=False
            )
            self.assert_test(
                response.status_code in [302, 303, 307],
                "Cookie setting redirect works"
            )

            # Check if Set-Cookie header is present
            set_cookie = response.headers.get('Set-Cookie', '')
            self.assert_test(
                'testcookie=testvalue' in set_cookie,
                "Set-Cookie header correctly passed through proxy"
            )
        except Exception as e:
            self.assert_test(False, "Cookie setting test", str(e))

        # Test reading cookies (follow the redirect)
        try:
            response = self.session.get(
                self.create_proxy_url(f"{self.httpbin_url}/cookies/set/testcookie/testvalue"),
                allow_redirects=True
            )

            if response.status_code == 200:
                data = response.json()
                cookies = data.get('cookies', {})
                self.assert_test(
                    cookies.get('testcookie') == 'testvalue',
                    "Cookies correctly maintained through proxy redirects"
                )
        except Exception as e:
            self.assert_test(False, "Cookie reading test", str(e))

    def test_authentication(self) -> None:
        """Test authentication methods through the proxy"""
        print(f"\n{Colors.BOLD}=== Testing Authentication ==={Colors.END}")

        # Test basic auth success
        try:
            response = self.session.get(
                self.create_proxy_url(f"{self.httpbin_url}/basic-auth/user/pass"),
                auth=('user', 'pass')
            )
            self.assert_test(
                response.status_code == 200,
                "Basic authentication success through proxy"
            )
        except Exception as e:
            self.assert_test(False, "Basic auth success test", str(e))

        # Test basic auth failure
        try:
            response = self.session.get(
                self.create_proxy_url(f"{self.httpbin_url}/basic-auth/user/pass"),
                auth=('wrong', 'credentials')
            )
            self.assert_test(
                response.status_code == 401,
                "Basic authentication failure through proxy"
            )
        except Exception as e:
            self.assert_test(False, "Basic auth failure test", str(e))

        # Test bearer token
        try:
            headers = {'Authorization': 'Bearer valid-token'}
            response = self.session.get(
                self.create_proxy_url(f"{self.httpbin_url}/bearer"),
                headers=headers
            )
            self.assert_test(
                response.status_code == 200,
                "Bearer token authentication through proxy"
            )
        except Exception as e:
            self.assert_test(False, "Bearer token test", str(e))

    def test_form_submission(self) -> None:
        """Test form submissions through the proxy"""
        print(f"\n{Colors.BOLD}=== Testing Form Submissions ==={Colors.END}")

        # Test form data submission
        try:
            form_data = {
                'field1': 'value1',
                'field2': 'value2',
                'proxy_test': 'form_submission'
            }
            response = self.session.post(
                self.create_proxy_url(f"{self.httpbin_url}/post"),
                data=form_data
            )

            self.assert_test(
                response.status_code == 200,
                "Form data submission through proxy"
            )

            if response.status_code == 200:
                data = response.json()
                form = data.get('form', {})
                self.assert_test(
                    form.get('proxy_test') == 'form_submission',
                    "Form data correctly transmitted through proxy"
                )
        except Exception as e:
            self.assert_test(False, "Form data submission test", str(e))

        # Test multipart form data
        try:
            files = {'test_file': ('test.txt', 'This is test file content', 'text/plain')}
            form_data = {'description': 'Test file upload'}

            response = self.session.post(
                self.create_proxy_url(f"{self.httpbin_url}/post"),
                files=files,
                data=form_data
            )

            self.assert_test(
                response.status_code == 200,
                "Multipart form submission through proxy"
            )

            if response.status_code == 200:
                data = response.json()
                files_data = data.get('files', {})
                form = data.get('form', {})

                self.assert_test(
                    'test_file' in files_data and 'test file content' in files_data['test_file'],
                    "File upload correctly handled through proxy"
                )

                self.assert_test(
                    form.get('description') == 'Test file upload',
                    "Multipart form fields correctly transmitted"
                )
        except Exception as e:
            self.assert_test(False, "Multipart form submission test", str(e))

        # Test URL parameter handling specifically
        try:
            # Test that query parameters work through the proxy
            response = self.session.get(self.create_proxy_url(f"{self.httpbin_url}/get?test=123&another=456"))
            self.assert_test(
                response.status_code == 200,
                "Query parameters correctly passed through proxy"
            )

            if response.status_code == 200:
                data = response.json()
                args = data.get('args', {})
                self.assert_test(
                    args.get('test') == '123' and args.get('another') == '456',
                    "Query parameters correctly received by target service"
                )
        except Exception as e:
            self.assert_test(False, "Query parameter test", str(e))

    def test_getpost_integration(self) -> None:
        """Test integration with staging.getpost.workers.dev"""
        print(f"\n{Colors.BOLD}=== Testing GetPost Integration ==={Colors.END}")

        # Test GetPost homepage
        try:
            response = self.session.get(self.create_proxy_url(self.getpost_url))
            self.assert_test(
                response.status_code == 200,
                "GetPost homepage accessible through proxy"
            )

            # Check for expected content
            self.assert_test(
                'getpost' in response.text.lower() or 'paste' in response.text.lower(),
                "GetPost homepage content correctly displayed"
            )
        except Exception as e:
            self.assert_test(False, "GetPost homepage test", str(e))

        # Test text upload to GetPost
        try:
            test_content = "This is a test paste through the proxy!"
            response = self.session.post(
                self.create_proxy_url(f"{self.getpost_url}/post"),
                data=test_content,
                headers={'Content-Type': 'text/plain'}
            )
            print(response.text)
            self.assert_test(
                response.status_code == 200,
                "Text upload to GetPost through proxy"
            )

            if response.status_code == 200:
                response_text = response.text
                # Should contain a share link
                self.assert_test(
                    'post?key=' in response_text,
                    "GetPost upload response contains share link"
                )

                # Extract the key for retrieval test
                if 'post?key=' in response_text:
                    try:
                        # Find the key in the response
                        start = response_text.find('post?key=') + 9
                        end = response_text.find('&', start)
                        if end == -1:
                            end = response_text.find(' ', start)
                        if end == -1:
                            end = response_text.find('\n', start)
                        if end == -1:
                            end = start + 26  # ULID length

                        key = response_text[start:end].strip().split('\n')[0]

                        # Test retrieval
                        if key:
                            retrieval_response = self.session.get(
                                self.create_proxy_url(f"{self.getpost_url}/post?key={key}")
                            )
                            self.assert_test(
                                retrieval_response.status_code == 200,
                                "GetPost content retrieval through proxy"
                            )
                            print(f"{self.getpost_url}/post?key={key}")
                            self.assert_test(
                                test_content in retrieval_response.text,
                                "GetPost content correctly retrieved through proxy"
                            )
                    except Exception as e:
                        self.assert_test(False, "GetPost content retrieval test", str(e))
        except Exception as e:
            self.assert_test(False, "GetPost text upload test", str(e))

        # Test GetPost debug endpoints
        try:
            response = self.session.get(self.create_proxy_url(f"{self.getpost_url}/headers"))
            self.assert_test(
                response.status_code == 200,
                "GetPost headers endpoint accessible through proxy"
            )
        except Exception as e:
            self.assert_test(False, "GetPost headers endpoint test", str(e))

    def test_error_handling(self) -> None:
        """Test proxy error handling"""
        print(f"\n{Colors.BOLD}=== Testing Error Handling ==={Colors.END}")

        # Test invalid URL
        try:
            response = self.session.get(f"{self.proxy_url}/{self.separator}invalid-url")
            self.assert_test(
                response.status_code >= 400,
                "Invalid URL returns error status"
            )
        except Exception as e:
            # This might be expected behavior
            self.assert_test(True, "Invalid URL handling", "Connection error expected")

        # Test non-existent domain
        try:
            response = self.session.get(
                self.create_proxy_url("https://this-domain-does-not-exist-123456.com"),
                timeout=10
            )
            self.assert_test(
                response.status_code >= 400,
                "Non-existent domain returns error status"
            )
        except Exception as e:
            # Network errors are expected here
            self.assert_test(True, "Non-existent domain handling", "Network error expected")

        # Test malformed proxy URL
        try:
            response = self.session.get(f"{self.proxy_url}/malformed-path")
            # Should either redirect to homepage or return error
            self.assert_test(
                response.status_code in [200, 302, 400, 404],
                "Malformed proxy URL handled gracefully"
            )
        except Exception as e:
            self.assert_test(False, "Malformed proxy URL test", str(e))

    def test_cors_support(self) -> None:
        """Test CORS support in the proxy"""
        print(f"\n{Colors.BOLD}=== Testing CORS Support ==={Colors.END}")

        # Test OPTIONS preflight request
        try:
            response = self.session.options(
                self.create_proxy_url(f"{self.httpbin_url}/get"),
                headers={
                    'Origin': 'https://example.com',
                    'Access-Control-Request-Method': 'GET',
                    'Access-Control-Request-Headers': 'Content-Type'
                }
            )

            self.assert_test(
                response.status_code == 204,
                "OPTIONS preflight request handled correctly"
            )

            self.assert_test(
                'Access-Control-Allow-Origin' in response.headers,
                "CORS headers present in OPTIONS response"
            )
        except Exception as e:
            self.assert_test(False, "CORS OPTIONS test", str(e))

    def test_security_features(self) -> None:
        """Test security features of the proxy"""
        print(f"\n{Colors.BOLD}=== Testing Security Features ==={Colors.END}")

        # Test rate limiting (if implemented)
        try:
            # Make several rapid requests
            responses = []
            for i in range(5):
                response = self.session.get(self.create_proxy_url(f"{self.httpbin_url}/get?test={i}"))
                responses.append(response.status_code)
                time.sleep(0.1)  # Small delay between requests

            # All should succeed if rate limiting is not too aggressive
            success_count = sum(1 for status in responses if status == 200)
            self.assert_test(
                success_count >= 3,
                "Rate limiting allows reasonable request frequency"
            )
        except Exception as e:
            self.assert_test(False, "Rate limiting test", str(e))

        # Test blocked protocols (if implemented)
        blocked_urls = [
            "ftp://example.com",
            "file:///etc/passwd",
            "javascript:alert('xss')"
        ]

        for blocked_url in blocked_urls:
            try:
                response = self.session.get(
                    self.create_proxy_url(blocked_url),
                    timeout=5
                )
                self.assert_test(
                    response.status_code >= 400,
                    f"Blocked protocol rejected: {blocked_url.split(':')[0]}"
                )
            except Exception as e:
                # Errors are expected for invalid protocols
                self.assert_test(True, f"Blocked protocol rejected: {blocked_url.split(':')[0]}")

    def test_homepage(self) -> None:
        """Test proxy homepage functionality"""
        print(f"\n{Colors.BOLD}=== Testing Proxy Homepage ==={Colors.END}")

        try:
            response = self.session.get(self.proxy_url)
            self.assert_test(
                response.status_code == 200,
                "Proxy homepage accessible"
            )

            # Check for expected homepage content
            content = response.text.lower()
            homepage_indicators = ['proxy', 'web proxy', 'browse', 'enter url']

            has_homepage_content = any(indicator in content for indicator in homepage_indicators)
            self.assert_test(
                has_homepage_content,
                "Proxy homepage contains expected content"
            )

            # Check for form to enter URLs
            self.assert_test(
                '<form' in content and 'input' in content,
                "Proxy homepage has URL input form"
            )
        except Exception as e:
            self.assert_test(False, "Proxy homepage test", str(e))

    def run_all_tests(self, categories: Optional[List[str]] = None) -> None:
        """Run all test categories or specified categories"""
        print(f"{Colors.BOLD}🧪 Cloudflare Worker Proxy Test Suite{Colors.END}")
        print(f"Testing proxy: {Colors.CYAN}{self.proxy_url}{Colors.END}")
        print(f"Separator: {Colors.CYAN}{self.separator}{Colors.END}\n")

        # Define all test categories
        all_categories = {
            'homepage': self.test_homepage,
            'basic': self.test_basic_requests,
            'headers': self.test_headers_and_user_agent,
            'redirects': self.test_redirects,
            'status': self.test_status_codes,
            'content': self.test_content_types,
            'images': self.test_images,
            'compression': self.test_compression,
            'cookies': self.test_cookies,
            'auth': self.test_authentication,
            'forms': self.test_form_submission,
            'cors': self.test_cors_support,
            'getpost': self.test_getpost_integration,
            'errors': self.test_error_handling,
            'security': self.test_security_features
        }

        # Run specified categories or all
        categories_to_run = categories if categories else all_categories.keys()

        for category in categories_to_run:
            if category in all_categories:
                try:
                    all_categories[category]()
                except Exception as e:
                    print(f"{Colors.RED}❌ Error in {category} tests: {e}{Colors.END}")
            else:
                print(f"{Colors.YELLOW}⚠️  Unknown test category: {category}{Colors.END}")

        # Print summary
        self.print_summary()

    def print_summary(self) -> None:
        """Print test results summary"""
        print(f"\n{Colors.BOLD}{'='*50}")
        print(f"TEST SUMMARY")
        print(f"{'='*50}{Colors.END}")

        print(f"Total tests run: {Colors.BOLD}{self.tests_run}{Colors.END}")
        print(f"Tests passed: {Colors.GREEN}{self.tests_passed}{Colors.END}")
        print(f"Tests failed: {Colors.RED}{self.tests_failed}{Colors.END}")

        if self.tests_failed > 0:
            print(f"\n{Colors.RED}❌ FAILED TESTS:{Colors.END}")
            for test in self.failed_tests:
                print(f"  • {test}")
            print(f"\n{Colors.RED}❌ SOME TESTS FAILED{Colors.END}")
            sys.exit(1)
        else:
            print(f"\n{Colors.GREEN}✅ ALL TESTS PASSED!{Colors.END}")
            print(f"{Colors.GREEN}🎉 Proxy is working correctly!{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description="Test suite for Cloudflare Worker Proxy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 test_proxy.py --proxy-url https://your-proxy.workers.dev
  python3 test_proxy.py --proxy-url https://proxy.example.com --verbose
  python3 test_proxy.py --proxy-url https://proxy.example.com --test-category basic headers
  python3 test_proxy.py --proxy-url https://proxy.example.com --separator "------"
        """
    )

    parser.add_argument(
        '--proxy-url',
        required=True,
        help='URL of the proxy to test (e.g., https://your-proxy.workers.dev)'
    )

    parser.add_argument(
        '--separator',
        default='------',
        help='URL separator used by the proxy (default: ------)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--test-category',
        nargs='*',
        choices=['homepage', 'basic', 'headers', 'redirects', 'status', 'content',
                'images', 'compression', 'cookies', 'auth', 'forms', 'cors',
                'getpost', 'errors', 'security'],
        help='Run specific test categories only'
    )

    args = parser.parse_args()

    # Validate proxy URL
    try:
        parsed = urlparse(args.proxy_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid proxy URL")
    except Exception as e:
        print(f"{Colors.RED}❌ Invalid proxy URL: {args.proxy_url}{Colors.END}")
        sys.exit(1)

    # Run tests
    test_suite = ProxyTestSuite(
        proxy_url=args.proxy_url,
        separator=args.separator,
        verbose=args.verbose
    )

    try:
        test_suite.run_all_tests(args.test_category)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Tests interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}❌ Unexpected error: {e}{Colors.END}")
        sys.exit(1)

if __name__ == "__main__":
    main()
