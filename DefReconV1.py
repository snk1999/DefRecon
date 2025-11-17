#!/usr/bin/env python3
"""
DefRecon - Advanced Defense Infrastructure Reconnaissance Tool
Detects firewalls, WAFs, backend technologies, and network infrastructure
"""

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests
import json
import dns.resolver
from ipwhois import IPWhois
import sys
import subprocess
import socket
import ssl
import os
import re
import time
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple

class DefRecon:
    def __init__(self, target_url: str, timeout: int = 10, verbose: bool = False):
        self.target_url = target_url
        self.host = self._extract_host(target_url)
        self.timeout = timeout
        self.verbose = verbose
        self.signals = {}
        self.components = []
        self.confidence_scores = {}
        
        # WAF signatures database
        self.waf_signatures = {
            'Cloudflare': ['cf-ray', '__cfduid', 'cloudflare'],
            'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
            'Akamai': ['akamai', 'x-akamai-transformed'],
            'Imperva': ['incap_ses', 'visid_incap', 'imperva'],
            'F5 BIG-IP': ['bigipserver', 'f5-trace-id', 'x-ws-security'],
            'Citrix NetScaler': ['ns_af=', 'citrix_ns_id', 'nsvpn'],
            'Barracuda': ['barra_counter_session', 'barracuda'],
            'ModSecurity': ['mod_security', 'naxsi'],
            'Sucuri': ['sucuri', 'x-sucuri'],
            'FortiWeb': ['fortigate', 'fortiweb'],
            'Wordfence': ['wordfence']
        }

    def _extract_host(self, url: str) -> str:
        """Extract hostname from URL or bare host"""
        parsed = urlparse(url if '://' in url else f'http://{url}')
        return parsed.hostname or url.split('/')[0]

    def _log(self, message: str):
        """Print verbose messages"""
        if self.verbose:
            print(f"[*] {message}")

    # ==================== COLLECTORS ====================
    
    def collect_http_headers(self) -> Dict:
        """Collect HTTP headers and analyze them for technology fingerprints"""
        try:
            self._log(f"Collecting HTTP headers from {self.target_url}")
            
            # Send request with common headers to avoid detection
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
            }
            
            response = requests.get(
                self.target_url, 
                timeout=self.timeout, 
                verify=False, 
                headers=headers,
                allow_redirects=True
            )
            
            resp_headers = dict(response.headers)
            
            # Extract key headers
            self.signals['http_status'] = response.status_code
            self.signals['server'] = resp_headers.get('Server', '')
            self.signals['x_powered_by'] = resp_headers.get('X-Powered-By', '')
            self.signals['all_headers'] = resp_headers
            self.signals['cookies'] = response.cookies.get_dict()
            self.signals['response_time'] = response.elapsed.total_seconds()
            
            # Analyze response body for fingerprints
            self._analyze_response_body(response.text)
            
            return resp_headers
            
        except requests.exceptions.SSLError as e:
            self._log(f"SSL Error: {e}")
            self.signals['server'] = "SSL Error"
            self.signals['ssl_error'] = str(e)
        except Exception as e:
            self._log(f"HTTP Collection Error: {e}")
            self.signals['server'] = f"error: {e}"
            self.signals['x_powered_by'] = ""
        
        return {}

    def _analyze_response_body(self, body: str):
        """Extract technology signatures from HTML response"""
        technologies = []
        
        # Meta generator tags
        meta_match = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', body, re.I)
        if meta_match:
            technologies.append({'source': 'meta_generator', 'value': meta_match.group(1)})
        
        # Common framework patterns
        patterns = {
            'WordPress': [r'wp-content/', r'wp-includes/'],
            'Drupal': [r'Drupal\.settings', r'sites/default/'],
            'Joomla': [r'option=com_', r'Joomla!'],
            'Django': [r'csrfmiddlewaretoken', r'__admin__'],
            'Laravel': [r'laravel_session', r'XSRF-TOKEN'],
            'React': [r'react', r'__REACT'],
            'Angular': [r'ng-', r'angular'],
            'Vue.js': [r'vue', r'v-'],
        }
        
        for tech, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, body, re.I):
                    technologies.append({'source': 'html_pattern', 'value': tech})
                    break
        
        self.signals['detected_technologies'] = technologies

    def collect_dns_info(self) -> Dict:
        """Collect DNS and network information"""
        try:
            self._log(f"Resolving DNS for {self.host}")
            
            # A records
            answers = dns.resolver.resolve(self.host, 'A')
            ips = [rdata.to_text() for rdata in answers]
            self.signals['dns_a'] = ips
            
            # CNAME records (CDN detection)
            try:
                cname_answers = dns.resolver.resolve(self.host, 'CNAME')
                cnames = [rdata.to_text() for rdata in cname_answers]
                self.signals['dns_cname'] = cnames
                self._detect_cdn_from_cname(cnames)
            except:
                self.signals['dns_cname'] = []
            
            # MX records
            try:
                mx_answers = dns.resolver.resolve(self.host, 'MX')
                mx_records = [rdata.to_text() for rdata in mx_answers]
                self.signals['dns_mx'] = mx_records
            except:
                self.signals['dns_mx'] = []
            
            # ASN and network info
            if ips:
                ip_info = IPWhois(ips[0]).lookup_rdap()
                self.signals['asn'] = ip_info.get('asn_description', 'unknown')
                self.signals['asn_number'] = ip_info.get('asn', 'unknown')
                self.signals['network'] = ip_info.get('network', {})
                self.signals['country'] = ip_info.get('asn_country_code', 'unknown')
            
            return {'ips': ips, 'asn': self.signals.get('asn')}
            
        except Exception as e:
            self._log(f"DNS Collection Error: {e}")
            self.signals['dns_a'] = [f"error: {e}"]
            self.signals['asn'] = "unknown"
            return {}

    def _detect_cdn_from_cname(self, cnames: List[str]):
        """Detect CDN from CNAME records"""
        cdn_patterns = {
            'Cloudflare': ['cloudflare'],
            'Akamai': ['akamai', 'edgesuite', 'edgekey'],
            'Fastly': ['fastly'],
            'CloudFront': ['cloudfront'],
            'MaxCDN': ['maxcdn'],
            'Incapsula': ['incapsula'],
        }
        
        detected_cdns = []
        for cname in cnames:
            cname_lower = cname.lower()
            for cdn, patterns in cdn_patterns.items():
                if any(pattern in cname_lower for pattern in patterns):
                    detected_cdns.append(cdn)
        
        if detected_cdns:
            self.signals['cdn_detected'] = detected_cdns

    def collect_tls_info(self) -> Dict:
        """Collect SSL/TLS information"""
        try:
            self._log(f"Collecting TLS info for {self.host}")
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.host, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    
                    self.signals['tls_version'] = ssock.version()
                    self.signals['cipher_suite'] = ssock.cipher()
                    self.signals['certificate'] = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                    }
                    
            return self.signals.get('tls_version', {})
            
        except Exception as e:
            self._log(f"TLS Collection Error: {e}")
            self.signals['tls_version'] = f"error: {e}"
            return {}

    # ==================== FIREWALL DETECTION ====================
    
    def _run_nmap(self, args: List[str]) -> str:
        """Run nmap scan with given arguments"""
        cmd = ["nmap"] + args + [self.host]
        try:
            self._log(f"Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=120
            )
            return result.stdout.lower()
        except subprocess.TimeoutExpired:
            return "error: scan timeout"
        except Exception as e:
            return f"error: {e}"

    def detect_firewall(self) -> Dict:
        """
        Multi-method firewall detection using parallel nmap scans
        and behavioral analysis
        """
        try:
            self._log("Starting firewall detection...")
            
            # Method 1: Simple connection test (doesn't require nmap)
            simple_firewall_check = self._simple_firewall_detection()
            
            # Method 2: Full nmap-based detection
            # Check if running as root for SYN scans
            is_root = os.geteuid() == 0 if hasattr(os, 'geteuid') else False
            scan_type = "-sS" if is_root else "-sT"
            
            if not is_root:
                self._log("Not running as root. Using TCP connect scan (-sT)")
            
            # Define scan configurations
            scans = {
                'syn': [scan_type, "-Pn", "-T3", "-p80,443,22,21,25,3389", "--max-retries=2"],
                'fin': ["-sF", "-Pn", "-T3", "-p80,443", "--max-retries=1"],
                'xmas': ["-sX", "-Pn", "-T3", "-p80,443", "--max-retries=1"],
                'null': ["-sN", "-Pn", "-T3", "-p80,443", "--max-retries=1"],
                'ack': ["-sA", "-Pn", "-T3", "-p80,443", "--max-retries=1"],
            }
            
            # Run scans in parallel
            results = {}
            with ThreadPoolExecutor(max_workers=5) as executor:
                future_to_scan = {
                    executor.submit(self._run_nmap, args): name 
                    for name, args in scans.items()
                }
                
                for future in as_completed(future_to_scan):
                    scan_name = future_to_scan[future]
                    try:
                        results[scan_name] = future.result()
                    except Exception as e:
                        results[scan_name] = f"error: {e}"
            
            # Analyze results
            evidence = self._analyze_firewall_evidence(results)
            
            # Merge simple detection results
            if simple_firewall_check['detected']:
                evidence['simple_detection'] = simple_firewall_check
            
            # Calculate firewall detection score with better logic
            score = 0
            
            # Simple detection adds points
            if simple_firewall_check['detected']:
                score += simple_firewall_check['confidence'] * 3
            
            # Strong evidence (stateful firewall behavior)
            if evidence.get('stateful_firewall'): 
                score += 4
            
            # Any filtered ports is evidence of filtering
            if evidence.get('filtering_detected'): 
                score += 2
            
            # Multiple scan types showing filtering
            filtered_count = sum([
                evidence.get('syn_filtered', False),
                evidence.get('fin_filtered', False),
                evidence.get('xmas_filtered', False),
                evidence.get('null_filtered', False),
                evidence.get('ack_filtered', False)
            ])
            score += filtered_count  # Add 1 point per filtered scan type
            
            # Inconsistent responses across scan types
            if evidence.get('inconsistent_responses'): 
                score += 3
            
            # High filtered port count
            if evidence.get('filtered_port_count', 0) >= 5:
                score += 2
            elif evidence.get('filtered_port_count', 0) >= 2:
                score += 1
            
            # Determine detection confidence
            detected = False
            certainty = "none"
            
            if score >= 7:
                detected = True
                certainty = "high"
            elif score >= 4:
                detected = True
                certainty = "medium"
            elif score >= 2:
                detected = True
                certainty = "low"
            
            self.signals['firewall'] = {
                "detected": detected,
                "certainty": certainty,
                "score": score,
                "max_score": 18,
                "evidence": evidence,
                "scan_results": results
            }
            
            self.confidence_scores['firewall'] = min(score / 18.0, 1.0)
            
            return self.signals['firewall']
            
        except Exception as e:
            self._log(f"Firewall Detection Error: {e}")
            self.signals['firewall'] = {
                "detected": False,
                "certainty": "error",
                "error": str(e)
            }
            return self.signals['firewall']

    def _simple_firewall_detection(self) -> Dict:
        """
        Simple firewall detection without nmap - tests common blocked ports
        """
        blocked_ports = []
        common_ports = [21, 22, 23, 25, 80, 443, 3389, 8080, 8443]
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.host, port))
                sock.close()
                
                # Connection refused (111) = port closed but reachable
                # Connection timeout = likely filtered by firewall
                if result != 0 and result != 111:  # Not open and not explicitly closed
                    blocked_ports.append(port)
                    
            except socket.timeout:
                blocked_ports.append(port)
            except Exception:
                pass
        
        # If multiple common ports are blocked/timeout, likely a firewall
        detected = len(blocked_ports) >= 3
        confidence = min(len(blocked_ports) / len(common_ports), 1.0)
        
        return {
            'detected': detected,
            'blocked_ports': blocked_ports,
            'tested_ports': common_ports,
            'confidence': confidence
        }

    def _analyze_firewall_evidence(self, results: Dict[str, str]) -> Dict:
        """Analyze nmap scan results for firewall evidence"""
        def is_filtered(text: str) -> bool:
            # Check for filtered ports or timeout indicators
            return ("filtered" in text) or ("no response" in text) or ("timeout" in text)
        
        def has_open_ports(text: str) -> bool:
            return "open" in text and "filtered" not in text
        
        def count_filtered(text: str) -> int:
            # Count how many times "filtered" appears
            return text.count("filtered")
        
        evidence = {
            'syn_filtered': is_filtered(results.get('syn', '')),
            'fin_filtered': is_filtered(results.get('fin', '')),
            'xmas_filtered': is_filtered(results.get('xmas', '')),
            'null_filtered': is_filtered(results.get('null', '')),
            'ack_filtered': is_filtered(results.get('ack', '')),
            'syn_has_open': has_open_ports(results.get('syn', '')),
            'inconsistent_responses': False,
            'filtered_port_count': sum(count_filtered(r) for r in results.values())
        }
        
        # Check for inconsistent responses (strong firewall indicator)
        # If different scan types show different results, likely a stateful firewall
        syn_state = 'open' if evidence['syn_has_open'] else ('filtered' if evidence['syn_filtered'] else 'closed')
        fin_state = 'filtered' if evidence['fin_filtered'] else 'open_or_closed'
        
        # Stateful firewalls allow SYN but drop FIN/XMAS/NULL
        if syn_state == 'open' and fin_state == 'filtered':
            evidence['inconsistent_responses'] = True
            evidence['stateful_firewall'] = True
        
        # If we see ANY filtered ports, there's likely a firewall
        if evidence['filtered_port_count'] > 0:
            evidence['filtering_detected'] = True
        
        return evidence

    # ==================== WAF DETECTION ====================
    
    def detect_waf(self) -> Dict:
        """
        Detect Web Application Firewall using multiple techniques:
        1. Header analysis
        2. Cookie patterns
        3. Malicious payload responses
        4. Response timing analysis
        """
        try:
            self._log("Starting WAF detection...")
            
            detected_wafs = []
            evidence = {}
            
            # 1. Check headers and cookies
            headers = self.signals.get('all_headers', {})
            cookies = self.signals.get('cookies', {})
            
            for waf_name, signatures in self.waf_signatures.items():
                # Check headers
                for header, value in headers.items():
                    if any(sig in header.lower() or sig in str(value).lower() 
                           for sig in signatures):
                        detected_wafs.append(waf_name)
                        evidence[waf_name] = f"Header: {header}"
                        break
                
                # Check cookies
                for cookie_name in cookies.keys():
                    if any(sig in cookie_name.lower() for sig in signatures):
                        if waf_name not in detected_wafs:
                            detected_wafs.append(waf_name)
                            evidence[waf_name] = f"Cookie: {cookie_name}"
            
            # 2. Test with malicious payloads
            payload_results = self._test_waf_payloads()
            
            if payload_results['blocked_count'] >= 2:
                if not detected_wafs:
                    detected_wafs.append("Generic WAF")
                evidence['payload_blocking'] = payload_results
            
            # 3. Response timing analysis
            timing_anomaly = self._check_timing_anomaly()
            if timing_anomaly:
                evidence['timing_anomaly'] = timing_anomaly
            
            # Calculate confidence score based on evidence strength
            confidence_score = 0.0
            if detected_wafs:
                confidence_score = 1.0  # WAF identified by signature
            elif payload_results['blocked_count'] >= 2:
                confidence_score = 0.7  # Blocking behavior without signature match
            elif payload_results['blocked_count'] == 1:
                confidence_score = 0.3  # Weak evidence of blocking
            
            confidence_level = "high" if confidence_score >= 0.8 else "medium" if confidence_score >= 0.4 else "low"
            
            self.signals['waf'] = {
                "detected": len(detected_wafs) > 0 or payload_results['blocked_count'] >= 2,
                "vendors": detected_wafs if detected_wafs else ["Generic/Unknown"] if payload_results['blocked_count'] >= 2 else [],
                "evidence": evidence,
                "confidence": confidence_level
            }
            
            self.confidence_scores['waf'] = confidence_score
            
            return self.signals['waf']
            
        except Exception as e:
            self._log(f"WAF Detection Error: {e}")
            self.signals['waf'] = {"detected": False, "error": str(e)}
            return self.signals['waf']

    def _test_waf_payloads(self) -> Dict:
        """Test WAF with malicious payloads"""
        payloads = [
            ("sql_injection", "?id=1' OR '1'='1"),
            ("xss", "?q=<script>alert(1)</script>"),
            ("path_traversal", "?file=../../../../etc/passwd"),
            ("command_injection", "?cmd=;cat /etc/passwd"),
        ]
        
        blocked_count = 0
        results = {}
        
        for payload_type, payload in payloads:
            try:
                url = self.target_url + payload
                response = requests.get(
                    url, 
                    timeout=self.timeout, 
                    verify=False,
                    allow_redirects=False
                )
                
                # WAF typically returns 403, 406, 419, 429, or specific block pages
                is_blocked = (
                    response.status_code in [403, 406, 419, 429] or
                    any(keyword in response.text.lower() 
                        for keyword in ['blocked', 'forbidden', 'security', 'firewall'])
                )
                
                if is_blocked:
                    blocked_count += 1
                    results[payload_type] = "blocked"
                else:
                    results[payload_type] = f"passed ({response.status_code})"
                    
                time.sleep(0.5)  # Avoid rate limiting
                
            except Exception as e:
                results[payload_type] = f"error: {e}"
        
        return {
            "blocked_count": blocked_count,
            "total_tests": len(payloads),
            "results": results
        }

    def _check_timing_anomaly(self) -> Optional[Dict]:
        """Check for response timing anomalies that may indicate WAF"""
        try:
            normal_time = self.signals.get('response_time', 0)
            
            # Send a suspicious request
            suspicious_url = self.target_url + "?id=1' OR '1'='1"
            start = time.time()
            requests.get(suspicious_url, timeout=self.timeout, verify=False)
            suspicious_time = time.time() - start
            
            # If suspicious request is significantly slower, might indicate WAF processing
            if suspicious_time > normal_time * 2 and suspicious_time > 1.0:
                return {
                    "normal_time": normal_time,
                    "suspicious_time": suspicious_time,
                    "difference": suspicious_time - normal_time
                }
        except:
            pass
        
        return None

    # ==================== ANALYSIS & REPORTING ====================
    
    def analyze_signals(self):
        """Analyze collected signals and identify components"""
        self._log("Analyzing signals...")
        
        # Web Server
        server = self.signals.get('server', '')
        if server and 'error' not in server.lower():
            self.components.append({
                "role": "Web Server",
                "vendor": server,
                "confidence": "high"
            })
        
        # Backend Framework
        powered_by = self.signals.get('x_powered_by', '')
        if powered_by:
            self.components.append({
                "role": "Backend Framework",
                "vendor": powered_by,
                "confidence": "high"
            })
        
        # Detected Technologies
        for tech in self.signals.get('detected_technologies', []):
            self.components.append({
                "role": "Technology",
                "vendor": tech['value'],
                "source": tech['source'],
                "confidence": "medium"
            })
        
        # CDN
        cdn = self.signals.get('cdn_detected', [])
        if cdn:
            self.components.append({
                "role": "CDN",
                "vendor": ', '.join(cdn),
                "confidence": "high"
            })
        
        # Network/ASN
        asn = self.signals.get('asn', '')
        if asn and asn != 'unknown':
            self.components.append({
                "role": "Network/ASN",
                "vendor": asn,
                "asn_number": self.signals.get('asn_number', ''),
                "country": self.signals.get('country', ''),
                "confidence": "high"
            })
        
        # Firewall
        fw = self.signals.get('firewall', {})
        if fw.get('detected'):
            self.components.append({
                "role": "Firewall",
                "vendor": f"Detected ({fw.get('certainty')})",
                "score": fw.get('score', 0),
                "confidence": fw.get('certainty')
            })
        
        # WAF
        waf = self.signals.get('waf', {})
        if waf.get('detected'):
            vendors = ', '.join(waf.get('vendors', ['Unknown']))
            self.components.append({
                "role": "Web Application Firewall",
                "vendor": vendors,
                "confidence": waf.get('confidence', 'medium')
            })
        
        # TLS
        tls_version = self.signals.get('tls_version', '')
        if tls_version and 'error' not in str(tls_version).lower():
            self.components.append({
                "role": "TLS/SSL",
                "version": tls_version,
                "cipher": self.signals.get('cipher_suite', [''])[0],
                "confidence": "high"
            })

    def build_schema(self) -> Dict:
        """Build final output schema"""
        return {
            "scan_info": {
                "target": self.target_url,
                "host": self.host,
                "timestamp": datetime.now().isoformat(),
                "scan_duration": "N/A"
            },
            "components": self.components,
            "detailed_signals": {
                "http": {
                    "status": self.signals.get('http_status'),
                    "server": self.signals.get('server'),
                    "powered_by": self.signals.get('x_powered_by'),
                    "response_time": self.signals.get('response_time'),
                    "technologies": self.signals.get('detected_technologies', [])
                },
                "network": {
                    "dns_a": self.signals.get('dns_a', []),
                    "dns_cname": self.signals.get('dns_cname', []),
                    "asn": self.signals.get('asn'),
                    "asn_number": self.signals.get('asn_number'),
                    "country": self.signals.get('country'),
                    "cdn": self.signals.get('cdn_detected', [])
                },
                "security": {
                    "firewall": self.signals.get('firewall', {}),
                    "waf": self.signals.get('waf', {}),
                    "tls": {
                        "version": self.signals.get('tls_version'),
                        "cipher": self.signals.get('cipher_suite')
                    }
                }
            },
            "confidence_scores": self.confidence_scores
        }

    def run_full_scan(self) -> Dict:
        """Execute complete reconnaissance scan"""
        start_time = time.time()
        
        print(f"\n{'='*60}")
        print(f"DefRecon - Security Reconnaissance Tool")
        print(f"Target: {self.target_url}")
        print(f"{'='*60}\n")
        
        # Collect all signals
        self.collect_http_headers()
        self.collect_dns_info()
        self.collect_tls_info()
        self.detect_firewall()
        self.detect_waf()
        
        # Analyze and build report
        self.analyze_signals()
        schema = self.build_schema()
        
        # Add scan duration
        scan_duration = time.time() - start_time
        schema['scan_info']['scan_duration'] = f"{scan_duration:.2f}s"
        
        return schema


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 DefRecon.py <url or host> [--verbose]")
        print("\nExample:")
        print("  python3 DefRecon.py https://example.com")
        print("  python3 DefRecon.py example.com --verbose")
        print("\nNote: Run with sudo for enhanced firewall detection (SYN scans)")
        sys.exit(1)
    
    target = sys.argv[1]
    verbose = '--verbose' in sys.argv or '-v' in sys.argv
    
    # Ensure URL has scheme
    if not target.startswith(('http://', 'https://')):
        target = f'https://{target}'
    
    try:
        scanner = DefRecon(target, verbose=verbose)
        results = scanner.run_full_scan()
        
        # Pretty print results
        print("\n" + "="*60)
        print("SCAN RESULTS")
        print("="*60 + "\n")
        print(json.dumps(results, indent=2))
        
        # Save to file
        output_file = f"defrecon_{scanner.host}_{int(time.time())}.json"
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to: {output_file}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()