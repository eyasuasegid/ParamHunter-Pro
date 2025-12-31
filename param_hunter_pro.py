#!/usr/bin/env python3
"""
PARAM-HUNTER PRO: Advanced Web Vulnerability Discovery Tool
Version: 3.0 - Penetration Testing Edition
Author: Security Research Team

Features:
- Advanced comment detection (HTML, JS, CSS, PHP, Python, etc.)
- Decoded string detection (Base64, URL, Hex, HTML entities)
- Input field identification with context
- Service/version detection
- Vulnerability pattern matching
"""

import os
import sys
import re
import json
import base64
import binascii
import html
from pathlib import Path
from urllib.parse import urlparse, parse_qs, unquote
from collections import defaultdict, Counter
import argparse
import chardet

class AdvancedParamHunter:
    def __init__(self):
        self.results = {
            'files_analyzed': 0,
            'html': defaultdict(list),
            'javascript': defaultdict(list),
            'css': defaultdict(list),
            'json': defaultdict(list),
            'php': defaultdict(list),
            'python': defaultdict(list),
            'config': defaultdict(list),
            'urls': defaultdict(list),
            'secrets': defaultdict(list),
            'endpoints': defaultdict(list),
            'cookies': defaultdict(list),
            'storage': defaultdict(list),
            'comments': defaultdict(list),
            'decoded_strings': defaultdict(list),
            'input_sections': defaultdict(list),
            'services': defaultdict(list),
            'vulnerabilities': defaultdict(list),
            'vulnerabilities': defaultdict(list),
            'patterns': defaultdict(list),
            'entropy': defaultdict(list),
            'cloud': defaultdict(list)
        }
        
        self.entropy_threshold = 4.5
        self.min_secret_length = 15
        
        # Enhanced regex patterns
        self.patterns = {
            # HTML Patterns
            'hidden_inputs': r'<input[^>]*type=["\']?hidden["\'][^>]*>',
            'all_inputs': r'<input[^>]*>',
            'form_fields': r'<(input|textarea|select|button)[^>]*name=["\']([^"\']+)["\'][^>]*>',
            'form_tags': r'<form[^>]*>.*?</form>',
            'input_sections': r'(?:<form[^>]*>.*?</form>|<input[^>]*>|<textarea[^>]*>.*?</textarea>|<select[^>]*>.*?</select>)',
            
            # JavaScript Patterns
            'js_variables': r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*(?:=\s*([^;\n]+))?',
            'js_functions': r'(?:function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)|([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*\([^)]*\)\s*=>)',
            'js_api_calls': r'(?:fetch|axios|jQuery\.(?:get|post)|\.ajax|XMLHttpRequest|http\.(?:get|post))[^;]*?[\'"]([^\'"]+)[\'"]',
            'js_secrets': r'(?:"|\')((?:api[_-]?key|secret[_-]?key?|token|password|auth[_-]?token?|access[_-]?token?|refresh[_-]?token?|client[_-]?(?:id|secret)|private[_-]?key|encryption[_-]?key))(?:"|\')\s*:\s*(?:"|\')([^"\']+)(?:"|\')',
            
            # Comment Patterns (MULTI-LANGUAGE)
            'html_comments': r'<!--(?!\[if\s+[^>]+>)(?!\[endif\]-->)(.*?)-->',
            'js_comments': r'(//[^\n]*|/\*[\s\S]*?\*/)',
            'css_comments': r'/\*[\s\S]*?\*/',
            'php_comments': r'(//[^\n]*|#.*|\/\*[\s\S]*?\*/)',
            'python_comments': r'#.*',
            'ruby_comments': r'#.*',
            'bash_comments': r'#.*',
            'xml_comments': r'<!--.*?-->',
            
            # Decoded String Patterns
            'base64_pattern': r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
            'hex_pattern': r'(?:\\x[0-9a-fA-F]{2})+|[0-9a-fA-F]{32,}',
            'url_encoded': r'%[0-9a-fA-F]{2}',
            'html_entities': r'&(?:[a-z0-9]+|#[0-9]{1,6}|#x[0-9a-fA-F]{1,6});',
            
            # Service/Version Detection
            'service_patterns': {
                'wordpress': r'(?:wp-content|wp-includes|wp-admin|\?p=|\?page_id=)',
                'joomla': r'(?:com_|option=com_|Itemid=)',
                'drupal': r'(?:sites/all/|\?q=node/)',
                'laravel': r'(?:Illuminate\\|@extends\([\'"]layouts|Route::)',
                'django': r'(?:{%|{{|url\(\'|from django\.)',
                'flask': r'(?:@app\.route|from flask import|url_for\(\))',
                'express': r'(?:require\(\'express\'|app\.(?:get|post)|res\.send\()',
                'react': r'(?:import React|ReactDOM\.render|className=)',
                'angular': r'(?:import {.*} from [\'"]@angular|ng-|\[\(|{{.*}})',
                'vue': r'(?:new Vue\(|v-|@click=|:src=)',
                'bootstrap': r'(?:bootstrap\.(?:min\.)?(?:css|js)|class=["\'].*?(?:btn|col|row|container))',
                'jquery': r'(?:jquery(?:\.min)?\.js|\$\(|\.ajax\(|jQuery\.)',
                'mysql': r'(?:mysql_connect|mysqli_|PDO\([\'"]mysql:)',
                'mongodb': r'(?:mongodb://|mongoose\.|ObjectId\()',
                'redis': r'(?:redis://|Redis\(|\.get\(|\.set\()',
            },
            
            # Version Patterns
            'version_patterns': [
                r'version["\']?\s*[:=]\s*["\']?([0-9]+\.[0-9]+(?:\.[0-9]+)?)["\']?',
                r'v\.?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'@version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
                r'Release\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            ],
            
            # Vulnerability Patterns
            'vuln_patterns': {
                'sql_injection': [
                    r'SELECT\s.*FROM.*WHERE.*\$\{?[a-zA-Z_]+\}?',
                    r'exec\(.*\$',
                    r'query\(.*["\'].*\$\{?[a-zA-Z_]+\}?',
                    r'\.raw\(.*\$',
                    r'unsafe.*query',
                ],
                'xss': [
                    r'innerHTML\s*=\s*[^;]*\$',
                    r'document\.write\([^;]*\$',
                    r'eval\([^;]*\$',
                    r'setAttribute\([^;]*["\']on\w+["\'][^;]*\$',
                    r'location\.(?:href|hash)\s*=\s*[^;]*\$',
                ],
                'command_injection': [
                    r'exec\([^;]*\$',
                    r'system\([^;]*\$',
                    r'passthru\([^;]*\$',
                    r'shell_exec\([^;]*\$',
                    r'popen\([^;]*\$',
                    r'proc_open\([^;]*\$',
                ],
                'path_traversal': [
                    r'\.\./',
                    r'\.\.\\',
                    r'include\([^;]*\$',
                    r'require\([^;]*\$',
                    r'file_get_contents\([^;]*\$',
                    r'readfile\([^;]*\$',
                ],
                'hardcoded_credentials': [
                    r'["\']password["\']\s*[:=]\s*["\'][^"\']{6,}["\']',
                    r'["\'](?:api[_-]?key|secret)["\']\s*[:=]\s*["\'][^"\']{8,}["\']',
                    r'(?:user|username|pass|pwd)\s*[:=]\s*["\'][^"\']{3,}["\']',
                    r'DB_(?:PASS|PASSWORD|USER)\s*[:=]\s*["\'][^"\']+["\']',
                ],
                'debug_mode': [
                    r'DEBUG\s*=\s*True',
                    r'debug\s*=\s*true',
                    r'app\.run\([^)]*debug\s*=\s*True',
                    r'error_reporting\(E_ALL\)',
                    r'display_errors\s*=\s*On',
                ],
            },
            
            # Config file patterns
            'config_files': [
                r'\.env',
                r'config\.(?:php|js|json|yml|yaml|toml|ini)',
                r'settings\.(?:php|js|json|py)',
                r'\.(?:gitignore|htaccess|dockerignore)',
            ],
            
            # URL Patterns
            'url_params': r'[?&]([a-zA-Z0-9_\-]+)(?:=([^&\s"\']*))?',
            'url_endpoints': r'["\']((?:https?:)?//[^"\']+?)["\']|\b(?:/api/|/v[0-9]/|/graphql|/rest/|/ws/|/wss/)[^"\'\s]*',
            
            # Storage Patterns
            'local_storage': r'localStorage\.(?:setItem|getItem|removeItem|clear)\s*\(\s*["\']([^"\']+)["\']',
            'session_storage': r'sessionStorage\.(?:setItem|getItem|removeItem|clear)\s*\(\s*["\']([^"\']+)["\']',
            'cookie_access': r'(?:document\.)?cookie\s*[=;]\s*([^=;\s]+)\s*=',

            # Missing Patterns
            'css_urls': r'url\s*\((?:["\']?)([^"\'\)]+)(?:["\']?)\)',
            'email_addresses': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'ip_addresses': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
            'phone_numbers': r'(?:\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}',
            'jwt_tokens': r'ey[A-Za-z0-9-_=]+\.ey[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*',
            
            # Cloud Infrastructure Patterns
            'cloud_infrastructure': {
                'aws_s3': r'(?i)[a-z0-9.-]+\.s3\.amazonaws\.com|[a-z0-9.-]+\.s3-[a-z0-9-]+\.amazonaws\.com|s3://[a-z0-9.-]+',
                'aws_key_id': r'(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])', # Case sensitive (Uppercase only)
                'google_storage': r'(?i)(?:storage\.googleapis\.com|storage\.cloud\.google\.com)/[a-z0-9.-]+',
                'azure_blob': r'(?i)[a-z0-9]+\.blob\.core\.windows\.net',
                'internal_ip': r'\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}\b',
                'cloud_metadata': r'169\.254\.169\.254',
            },

            # Dangerous Sinks (DOM XSS)
            'dangerous_sinks': r'(?:dangerouslySetInnerHTML|bypassSecurityTrustHtml|eval\(|exec\(|\.innerHTML\s*=|document\.write\()',
        }
        
        self.sensitive_keywords = [
            'password', 'passwd', 'pwd', 'secret', 'key', 'token', 'auth',
            'credential', 'login', 'signin', 'admin', 'private', 'hidden',
            'api_key', 'access_key', 'secret_key', 'jwt', 'bearer', 'oauth',
            'session', 'cookie', 'csrf', 'xsrf', 'nonce', 'salt', 'hash',
            'credit', 'card', 'cvv', 'ssn', 'social', 'security', 'phone',
            'email', 'address', 'birth', 'dob', 'zip', 'pin', 'code',
            'bank', 'account', 'routing', 'iban', 'swift', 'crypto',
            'private_key', 'public_key', 'ssh', 'rsa', 'dsa', 'ecdsa',
            'aws_key', 'azure_key', 'gcp_key', 'stripe_key', 'paypal_key',
            'github_token', 'gitlab_token', 'slack_token', 'discord_token',
            'firebase_key', 'mongodb_uri', 'postgres_uri', 'redis_uri',
            'jira_token', 'confluence_token', 'jenkins_token',
        ]

    def detect_encoding(self, file_path):
        """Detect file encoding"""
        try:
            with open(file_path, 'rb') as f:
                raw_data = f.read()
                result = chardet.detect(raw_data)
                return result['encoding'] or 'utf-8'
        except:
            return 'utf-8'

    def analyze_file(self, file_path):
        """Analyze a single file with advanced detection"""
        try:
            encoding = self.detect_encoding(file_path)
            with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                content = f.read()
        except Exception as e:
            return f"Error reading {file_path}: {e}"
        
        self.results['files_analyzed'] += 1
        file_ext = os.path.splitext(file_path)[1].lower()
        file_name = os.path.basename(file_path)
        
        # Detect file type and analyze
        if file_ext in ['.html', '.htm', '.xhtml']:
            self._analyze_html(content, file_path)
        elif file_ext in ['.php', '.phtml']:
            self._analyze_php(content, file_path)
        elif file_ext in ['.js', '.jsx', '.mjs']:
            self._analyze_javascript(content, file_path)
        elif file_ext in ['.ts', '.tsx']:
            self._analyze_typescript(content, file_path)
        elif file_ext in ['.css', '.scss', '.sass', '.less']:
            self._analyze_css(content, file_path)
        elif file_ext in ['.json', '.json5']:
            self._analyze_json(content, file_path)
        elif file_ext in ['.py', '.pyw']:
            self._analyze_python(content, file_path)
        elif file_ext in ['.rb', '.erb']:
            self._analyze_ruby(content, file_path)
        elif file_ext in ['.java', '.jsp']:
            self._analyze_java(content, file_path)
        elif any(re.search(pattern, file_name, re.IGNORECASE) for pattern in self.patterns['config_files']):
            self._analyze_config(content, file_path)
        else:
            # Generic text file analysis
            self._analyze_generic(content, file_path)
        
        # Always run these universal checks
        self._detect_decoded_strings(content, file_path)
        self._detect_services_versions(content, file_path)
        self._detect_vulnerability_patterns(content, file_path)
        self._detect_entropy(content, file_path)
        self._detect_cloud_infrastructure(content, file_path)
        self._extract_urls(content, file_path, 'universal')
        
        return f"Analyzed {file_path}"

    def _analyze_html(self, content, file_path):
        """Analyze HTML content with advanced detection"""
        # Input sections
        input_matches = re.finditer(self.patterns['input_sections'], content, re.IGNORECASE | re.DOTALL)
        for match in input_matches:
            section = match.group()
            self.results['input_sections']['html'].append({
                'file': file_path,
                'section': section[:500],
                'line': self._get_line_number(content, match.start())
            })
        
        # Hidden inputs
        hidden_matches = re.finditer(self.patterns['hidden_inputs'], content, re.IGNORECASE)
        for match in hidden_matches:
            field_html = match.group()
            name = self._extract_attribute(field_html, 'name')
            value = self._extract_attribute(field_html, 'value')
            id_attr = self._extract_attribute(field_html, 'id')
            self.results['html']['hidden_fields'].append({
                'file': file_path,
                'name': name,
                'value': value,
                'id': id_attr,
                'html': field_html[:200],
                'line': self._get_line_number(content, match.start())
            })
        
        # All form fields
        field_matches = re.finditer(self.patterns['form_fields'], content, re.IGNORECASE | re.DOTALL)
        for match in field_matches:
            tag, name = match.groups()
            field_html = match.group()
            value = self._extract_attribute(field_html, 'value')
            type_attr = self._extract_attribute(field_html, 'type')
            
            if type_attr and 'hidden' in type_attr.lower():
                continue
            
            self.results['html']['visible_fields'].append({
                'file': file_path,
                'tag': tag,
                'name': name,
                'type': type_attr,
                'value': value,
                'html': field_html[:200],
                'line': self._get_line_number(content, match.start())
            })
        
        # Forms
        form_matches = re.finditer(self.patterns['form_tags'], content, re.IGNORECASE | re.DOTALL)
        for match in form_matches:
            form_html = match.group()
            action = self._extract_attribute(form_html, 'action')
            method = self._extract_attribute(form_html, 'method')
            self.results['html']['forms'].append({
                'file': file_path,
                'action': action,
                'method': method,
                'html': form_html[:500],
                'line': self._get_line_number(content, match.start())
            })
        
        # HTML comments (RELIABLE DETECTION)
        comment_matches = re.finditer(self.patterns['html_comments'], content, re.DOTALL)
        for match in comment_matches:
            comment = match.group(1).strip()
            if comment and len(comment) > 5:
                self.results['comments']['html'].append({
                    'file': file_path,
                    'comment': comment[:1000],
                    'line': self._get_line_number(content, match.start())
                })
        
        # Inline JavaScript
        script_pattern = r'<script[^>]*>([\s\S]*?)</script>'
        script_matches = re.finditer(script_pattern, content, re.IGNORECASE)
        for match in script_matches:
            script_content = match.group(1)
            self._analyze_javascript(script_content, f"{file_path} (inline)")
        
        # Inline CSS
        style_pattern = r'<style[^>]*>([\s\S]*?)</style>'
        style_matches = re.finditer(style_pattern, content, re.IGNORECASE)
        for match in style_matches:
            style_content = match.group(1)
            self._analyze_css(style_content, f"{file_path} (inline)")

    def _analyze_php(self, content, file_path):
        """Analyze PHP files"""
        # PHP comments
        comment_matches = re.finditer(self.patterns['php_comments'], content)
        for match in comment_matches:
            comment = match.group().strip()
            if comment and len(comment) > 10:
                self.results['comments']['php'].append({
                    'file': file_path,
                    'comment': comment[:500],
                    'line': self._get_line_number(content, match.start())
                })
        
        # Database connections
        db_patterns = [
            r'mysql_connect\([^)]+\)',
            r'mysqli_connect\([^)]+\)',
            r'new\s+PDO\([^)]+\)',
            r'\$db(?:name|host|user|pass)\s*=',
        ]
        
        for pattern in db_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self.results['php']['db_connections'].append({
                    'file': file_path,
                    'code': match.group()[:200],
                    'line': self._get_line_number(content, match.start())
                })
        
        # Include/require statements
        include_matches = re.finditer(r'(?:include|require)(?:_once)?\s*\(?\s*[\'"]([^\'"]+)[\'"]', content)
        for match in include_matches:
            include_file = match.group(1)
            self.results['php']['includes'].append({
                'file': file_path,
                'included': include_file,
                'line': self._get_line_number(content, match.start())
            })

    def _analyze_javascript(self, content, file_path):
        """Analyze JavaScript content"""
        # JS comments (RELIABLE DETECTION)
        comment_matches = re.finditer(self.patterns['js_comments'], content, re.DOTALL)
        for match in comment_matches:
            comment = match.group().strip()
            if comment and len(comment) > 10:
                self.results['comments']['javascript'].append({
                    'file': file_path,
                    'comment': comment[:500],
                    'line': self._get_line_number(content, match.start())
                })
        
        # Sensitive variables
        var_matches = re.finditer(self.patterns['js_variables'], content)
        for match in var_matches:
            name, value = match.groups()
            if name and any(kw in name.lower() for kw in self.sensitive_keywords):
                self.results['javascript']['sensitive_vars'].append({
                    'file': file_path,
                    'name': name,
                    'value': str(value)[:200] if value else None,
                    'line': self._get_line_number(content, match.start())
                })
        
        # API calls
        api_matches = re.finditer(self.patterns['js_api_calls'], content)
        for match in api_matches:
            endpoint = match.group(1)
            self.results['endpoints']['api_calls'].append({
                'file': file_path,
                'endpoint': endpoint,
                'context': self._get_context(content, match.start(), 100),
                'line': self._get_line_number(content, match.start())
            })
        
        # Secrets
        secret_matches = re.finditer(self.patterns['js_secrets'], content, re.IGNORECASE)
        for match in secret_matches:
            key, value = match.groups()
            self.results['secrets']['js_secrets'].append({
                'file': file_path,
                'key': key,
                'value': value[:200],
                'context': self._get_context(content, match.start(), 100),
                'line': self._get_line_number(content, match.start())
            })
        
        # Storage access
        ls_matches = re.finditer(self.patterns['local_storage'], content)
        for match in ls_matches:
            key = match.group(1)
            self.results['storage']['local_storage'].append({
                'file': file_path,
                'key': key,
                'context': self._get_context(content, match.start(), 100),
                'line': self._get_line_number(content, match.start())
            })
        
        ss_matches = re.finditer(self.patterns['session_storage'], content)
        for match in ss_matches:
            key = match.group(1)
            self.results['storage']['session_storage'].append({
                'file': file_path,
                'key': key,
                'context': self._get_context(content, match.start(), 100),
                'line': self._get_line_number(content, match.start())
            })
        
        # Cookies
        cookie_matches = re.finditer(self.patterns['cookie_access'], content)
        for match in cookie_matches:
            cookie_name = match.group(1)
            self.results['cookies']['js_cookies'].append({
                'file': file_path,
                'name': cookie_name,
                'context': self._get_context(content, match.start(), 100),
                'line': self._get_line_number(content, match.start())
            })

    def _analyze_typescript(self, content, file_path):
        """Analyze TypeScript content"""
        # Inherit JS analysis
        self._analyze_javascript(content, file_path)
        
        # TypeScript specific patterns
        interface_matches = re.finditer(r'interface\s+([A-Z][a-zA-Z0-9_]*)\s*{', content)
        for match in interface_matches:
            interface_name = match.group(1)
            self.results['patterns']['typescript_interfaces'].append({
                'file': file_path,
                'interface': interface_name,
                'line': self._get_line_number(content, match.start())
            })

    def _analyze_css(self, content, file_path):
        """Analyze CSS content"""
        # CSS comments (RELIABLE DETECTION)
        comment_matches = re.finditer(self.patterns['css_comments'], content, re.DOTALL)
        for match in comment_matches:
            comment = match.group().strip()
            if comment and len(comment) > 10:
                self.results['comments']['css'].append({
                    'file': file_path,
                    'comment': comment[:500],
                    'line': self._get_line_number(content, match.start())
                })
        
        # URLs in CSS
        url_matches = re.finditer(self.patterns['css_urls'], content)
        for match in url_matches:
            url = match.group(1)
            if '?' in url:
                base, query = url.split('?', 1)
                params = parse_qs(query)
                for param, values in params.items():
                    for value in values:
                        self.results['urls']['css_urls'].append({
                            'file': file_path,
                            'url': base,
                            'param': param,
                            'value': value[:200],
                            'line': self._get_line_number(content, match.start())
                        })

    def _analyze_json(self, content, file_path):
        """Analyze JSON content"""
        try:
            data = json.loads(content)
            self._traverse_json(data, [], file_path)
        except json.JSONDecodeError:
            # Try to find JSON-like structures
            json_like_pattern = r'\{[^}]*:[^}]*\}'
            matches = re.finditer(json_like_pattern, content)
            for match in matches:
                try:
                    partial_data = json.loads(match.group())
                    self._traverse_json(partial_data, [], file_path)
                except:
                    pass

    def _traverse_json(self, data, path, file_path):
        """Recursively traverse JSON for sensitive data"""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = path + [key]
                key_str = '.'.join(current_path)
                
                # Check for sensitive keys
                key_lower = key.lower()
                if any(kw in key_lower for kw in self.sensitive_keywords):
                    self.results['secrets']['json_secrets'].append({
                        'file': file_path,
                        'key': key_str,
                        'value': str(value)[:200] if value else None,
                        'full_path': ' -> '.join(current_path)
                    })
                
                # Check for URLs
                if isinstance(value, str):
                    if 'http://' in value or 'https://' in value:
                        self.results['urls']['json_urls'].append({
                            'file': file_path,
                            'key': key_str,
                            'url': value,
                            'full_path': ' -> '.join(current_path)
                        })
                
                self._traverse_json(value, current_path, file_path)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._traverse_json(item, path + [str(i)], file_path)

    def _analyze_python(self, content, file_path):
        """Analyze Python files"""
        # Python comments
        comment_matches = re.finditer(self.patterns['python_comments'], content)
        for match in comment_matches:
            comment = match.group().strip()
            if comment and len(comment) > 10:
                self.results['comments']['python'].append({
                    'file': file_path,
                    'comment': comment[:500],
                    'line': self._get_line_number(content, match.start())
                })
        
        # Django templates
        django_patterns = [
            r'\{%\s*(?:if|for|block|extends|include)\s+',
            r'\{\{\s*[^}]+\s*\}\}',
        ]
        
        for pattern in django_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                self.results['patterns']['django_templates'].append({
                    'file': file_path,
                    'template': match.group()[:200],
                    'line': self._get_line_number(content, match.start())
                })

    def _analyze_ruby(self, content, file_path):
        """Analyze Ruby files"""
        # Ruby comments
        comment_matches = re.finditer(self.patterns['ruby_comments'], content)
        for match in comment_matches:
            comment = match.group().strip()
            if comment and len(comment) > 10:
                self.results['comments']['ruby'].append({
                    'file': file_path,
                    'comment': comment[:500],
                    'line': self._get_line_number(content, match.start())
                })

    def _analyze_java(self, content, file_path):
        """Analyze Java files"""
        # Java comments
        java_comment_pattern = r'(//[^\n]*|/\*[\s\S]*?\*/)'
        comment_matches = re.finditer(java_comment_pattern, content)
        for match in comment_matches:
            comment = match.group().strip()
            if comment and len(comment) > 10:
                self.results['comments']['java'].append({
                    'file': file_path,
                    'comment': comment[:500],
                    'line': self._get_line_number(content, match.start())
                })

    def _analyze_config(self, content, file_path):
        """Analyze configuration files"""
        # Look for key-value pairs
        kv_pattern = r'([A-Za-z0-9_]+)\s*[=:]\s*([^\n]+)'
        matches = re.finditer(kv_pattern, content)
        
        for match in matches:
            key, value = match.groups()
            key_lower = key.lower()
            
            if any(kw in key_lower for kw in self.sensitive_keywords):
                self.results['config']['sensitive_configs'].append({
                    'file': file_path,
                    'key': key,
                    'value': value.strip()[:200],
                    'line': self._get_line_number(content, match.start())
                })
            else:
                self.results['config']['general_configs'].append({
                    'file': file_path,
                    'key': key,
                    'value': value.strip()[:200],
                    'line': self._get_line_number(content, match.start())
                })

    def _analyze_generic(self, content, file_path):
        """Analyze generic text files"""
        # Universal comment detection
        comment_patterns = [
            (self.patterns['python_comments'], 'python'),
            (self.patterns['bash_comments'], 'bash'),
            (self.patterns['xml_comments'], 'xml'),
        ]
        
        for pattern, lang in comment_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                comment = match.group().strip()
                if comment and len(comment) > 10:
                    self.results['comments'][lang].append({
                        'file': file_path,
                        'comment': comment[:500],
                        'line': self._get_line_number(content, match.start())
                    })
        
        # Email addresses
        email_matches = re.finditer(self.patterns['email_addresses'], content)
        for match in email_matches:
            email = match.group()
            self.results['secrets']['emails'].append({
                'file': file_path,
                'email': email,
                'line': self._get_line_number(content, match.start())
            })
        
        # IP addresses
        ip_matches = re.finditer(self.patterns['ip_addresses'], content)
        for match in ip_matches:
            ip = match.group()
            self.results['secrets']['ips'].append({
                'file': file_path,
                'ip': ip,
                'line': self._get_line_number(content, match.start())
            })
        
        # Phone numbers
        phone_matches = re.finditer(self.patterns['phone_numbers'], content)
        for match in phone_matches:
            phone = match.group()
            self.results['secrets']['phones'].append({
                'file': file_path,
                'phone': phone,
                'line': self._get_line_number(content, match.start())
            })
        
        # JWT tokens
        jwt_matches = re.finditer(self.patterns['jwt_tokens'], content)
        for match in jwt_matches:
            jwt = match.group()
            self.results['secrets']['jwts'].append({
                'file': file_path,
                'jwt': jwt[:100],
                'line': self._get_line_number(content, match.start())
            })

    def _detect_decoded_strings(self, content, file_path):
        """Detect and decode encoded strings"""
        # Base64 detection and decoding
        base64_matches = re.finditer(r'["\']([A-Za-z0-9+/=]{20,})["\']', content)
        for match in base64_matches:
            encoded = match.group(1)
            try:
                decoded = base64.b64decode(encoded).decode('utf-8', errors='ignore')
                if len(decoded) > 3 and any(c.isprintable() and not c.isspace() for c in decoded):
                    self.results['decoded_strings']['base64'].append({
                        'file': file_path,
                        'encoded': encoded[:100],
                        'decoded': decoded[:200],
                        'line': self._get_line_number(content, match.start())
                    })
            except:
                pass
        
        # URL encoded detection
        url_encoded_matches = re.finditer(r'["\']((?:%[0-9a-fA-F]{2}){3,})["\']', content)
        for match in url_encoded_matches:
            encoded = match.group(1)
            try:
                decoded = unquote(encoded)
                if decoded != encoded and len(decoded) > 3:
                    self.results['decoded_strings']['url'].append({
                        'file': file_path,
                        'encoded': encoded[:100],
                        'decoded': decoded[:200],
                        'line': self._get_line_number(content, match.start())
                    })
            except:
                pass
        
        # Hex encoded detection
        hex_matches = re.finditer(r'["\']((?:\\x[0-9a-fA-F]{2}){3,})["\']', content)
        for match in hex_matches:
            encoded = match.group(1)
            try:
                decoded = bytes.fromhex(encoded.replace('\\x', '')).decode('utf-8', errors='ignore')
                if len(decoded) > 3:
                    self.results['decoded_strings']['hex'].append({
                        'file': file_path,
                        'encoded': encoded[:100],
                        'decoded': decoded[:200],
                        'line': self._get_line_number(content, match.start())
                    })
            except:
                pass
        
        # HTML entities detection
        html_entity_matches = re.finditer(r'["\']((?:&[a-z0-9#]+;){3,})["\']', content)
        for match in html_entity_matches:
            encoded = match.group(1)
            try:
                decoded = html.unescape(encoded)
                if decoded != encoded:
                    self.results['decoded_strings']['html_entities'].append({
                        'file': file_path,
                        'encoded': encoded[:100],
                        'decoded': decoded[:200],
                        'line': self._get_line_number(content, match.start())
                    })
            except:
                pass

    def _detect_services_versions(self, content, file_path):
        """Detect services and versions"""
        # Service detection
        for service, pattern in self.patterns['service_patterns'].items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                self.results['services']['detected'].append({
                    'file': file_path,
                    'service': service,
                    'evidence': match.group()[:100],
                    'line': self._get_line_number(content, match.start())
                })
        
        # Version detection
        for pattern in self.patterns['version_patterns']:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                version = match.group(1)
                self.results['services']['versions'].append({
                    'file': file_path,
                    'version': version,
                    'context': self._get_context(content, match.start(), 50),
                    'line': self._get_line_number(content, match.start())
                })
        
        # Framework-specific version patterns
        framework_patterns = {
            'jquery': r'jquery[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'bootstrap': r'bootstrap[.-]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'react': r'react[.-/]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'vue': r'vue[.-/]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
            'angular': r'angular[.-/]([0-9]+\.[0-9]+(?:\.[0-9]+)?)',
        }
        
        for framework, pattern in framework_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                version = match.group(1)
                self.results['services']['framework_versions'].append({
                    'file': file_path,
                    'framework': framework,
                    'version': version,
                    'line': self._get_line_number(content, match.start())
                })

    def _detect_vulnerability_patterns(self, content, file_path):
        """Detect vulnerability patterns"""
        for vuln_type, patterns in self.patterns['vuln_patterns'].items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    self.results['vulnerabilities'][vuln_type].append({
                        'file': file_path,
                        'pattern': pattern[:100],
                        'code': match.group()[:200],
                        'line': self._get_line_number(content, match.start()),
                        'context': self._get_context(content, match.start(), 100)
                    })

    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(text.count(chr(x))) / len(text)
            if p_x > 0:
                import math
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _detect_entropy(self, content, file_path):
        """Detect high entropy strings that might be secrets"""
        # Find string literals
        strings = re.finditer(r'(["\'])(.*?)\1', content)
        for match in strings:
            string_val = match.group(2)
            if len(string_val) > self.min_secret_length:
                # Skip if it contains too many spaces (likely text)
                if string_val.count(' ') > 2:
                    continue
                
                entropy = self._calculate_entropy(string_val)
                if entropy > self.entropy_threshold:
                    self.results['entropy']['high_entropy_strings'].append({
                        'file': file_path,
                        'value': string_val[:50],  # Truncate for display
                        'entropy': f"{entropy:.2f}",
                        'line': self._get_line_number(content, match.start())
                    })

    def _detect_cloud_infrastructure(self, content, file_path):
        """Detect cloud infrastructure and dangerous patterns"""
        # Cloud patterns
        for key, pattern in self.patterns['cloud_infrastructure'].items():
            # NOTE: re.IGNORECASE is NOT used here to allow aws_key_id to be case-sensitive.
            # Patterns that need valid case-insensitivity (like domains) use (?i) in the regex.
            matches = re.finditer(pattern, content)
            for match in matches:
                self.results['cloud']['infrastructure'].append({
                    'file': file_path,
                    'type': key,
                    'value': match.group(),
                    'line': self._get_line_number(content, match.start())
                })
                
        # Dangerous sinks
        matches = re.finditer(self.patterns['dangerous_sinks'], content)
        for match in matches:
            self.results['vulnerabilities']['dangerous_sink'].append({
                'file': file_path,
                'sink': match.group(),
                'line': self._get_line_number(content, match.start()),
                'context': self._get_context(content, match.start(), 100)
            })

    def _extract_urls(self, content, file_path, source_type):
        """Extract URLs and their parameters"""
        # URL parameters
        param_matches = re.finditer(self.patterns['url_params'], content)
        for match in param_matches:
            param, value = match.groups()
            self.results['urls']['parameters'].append({
                'file': file_path,
                'source': source_type,
                'param': param,
                'value': value[:200] if value else '',
                'context': self._get_context(content, match.start(), 100),
                'line': self._get_line_number(content, match.start())
            })
        
        # Endpoints
        endpoint_matches = re.finditer(self.patterns['url_endpoints'], content)
        for match in endpoint_matches:
            endpoint = match.group(1) or match.group(2)
            if endpoint:
                self.results['endpoints'][source_type].append({
                    'file': file_path,
                    'endpoint': endpoint,
                    'line': self._get_line_number(content, match.start())
                })

    def _extract_attribute(self, html, attribute):
        """Extract attribute value from HTML tag"""
        pattern = rf'{attribute}\s*=\s*["\']([^"\']*)["\']'
        match = re.search(pattern, html, re.IGNORECASE)
        return match.group(1) if match else None

    def _get_context(self, content, position, chars=50):
        """Get context around a position"""
        start = max(0, position - chars)
        end = min(len(content), position + chars)
        return content[start:end]

    def _get_line_number(self, content, position):
        """Get line number from position in content"""
        return content[:position].count('\n') + 1

    def scan_directory(self, directory):
        """Scan all files in a directory"""
        print(f"🔍 Starting scan of directory: {directory}")
        files_processed = 0
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.startswith('.'):
                    continue
                file_path = os.path.join(root, file)
                try:
                    # Calculate findings before analysis
                    before_findings = sum(len(items) for cat in self.results.values() if isinstance(cat, dict) for items in cat.values())
                    
                    self.analyze_file(file_path)
                    files_processed += 1
                    
                    # Calculate findings after analysis
                    after_findings = sum(len(items) for cat in self.results.values() if isinstance(cat, dict) for items in cat.values())
                    new_findings = after_findings - before_findings
                    
                    print(f"✅ Analyzed: {file_path}")
                    if new_findings > 0:
                        print(f"   => Found {new_findings} items in this file")
                    else:
                        print(f"   => Clean (no issues found)")
                        
                except Exception as e:
                    print(f"❌ Error analyzing {file_path}: {e}")
        
        print(f"\n🏁 Scan complete. Processed {files_processed} files.")

    def generate_report(self, output_file=None, show_categories=None):
        """
        Generate a detailed penetration testing report
        show_categories: list of categories to show details for (e.g. ['html', 'secrets'])
        """
        show_categories = [c.lower() for c in (show_categories or [])]
        show_all = 'all' in show_categories
        
        def should_show(category):
            return show_all or category in show_categories
        report = []
        
        report.append("=" * 90)
        report.append("PARAM-HUNTER PRO - PENETRATION TESTING REPORT")
        report.append("=" * 90)
        
        # Summary
        total_findings = 0
        for category in self.results.values():
            if isinstance(category, dict):
                for items in category.values():
                    if isinstance(items, list):
                        total_findings += len(items)
        report.append(f"\n📊 SUMMARY")
        report.append("-" * 40)
        report.append(f"  Files Analyzed: {self.results['files_analyzed']}")
        report.append(f"  Total Findings: {total_findings}")
        
        # HTML Findings
        if self.results['html']:
            report.append(f"\n🔍 HTML ANALYSIS")
            report.append("-" * 40)
            
            hidden_count = len(self.results['html']['hidden_fields'])
            visible_count = len(self.results['html']['visible_fields'])
            forms_count = len(self.results['html']['forms'])
            input_sections = len(self.results['input_sections']['html'])
            
            report.append(f"  Hidden Input Fields: {hidden_count}")
            report.append(f"  Visible Input Fields: {visible_count}")
            report.append(f"  Forms: {forms_count}")
            report.append(f"  Input Sections: {input_sections}")
            
            if hidden_count > 0:
                if should_show('html'):
                    report.append(f"\n  🚨 HIDDEN FIELDS FOUND ({hidden_count}):")
                    for i, field in enumerate(self.results['html']['hidden_fields'], 1):
                        report.append(f"    {i}. File: {field['file']}")
                        report.append(f"       Line: {field['line']}")
                        report.append(f"       Name: {field['name']}")
                        report.append(f"       Value: {field['value']}")
                        if field['id']:
                            report.append(f"       ID: {field['id']}")
                else:
                    report.append(f"\n  [!] {hidden_count} Hidden Fields found. Use '-l html' to list.")
        
        # Comments Analysis
        total_comments = sum(len(comments) for comments in self.results['comments'].values())
        if total_comments > 0:
            report.append(f"\n💬 COMMENTS FOUND ({total_comments})")
            report.append("-" * 40)
            
            # Helper to check if a specific language should be shown
            # Standard web languages
            standard_web_langs = {'html', 'css', 'javascript', 'js', 'php'}
            # All valid comment languages
            valid_langs = standard_web_langs | {'python', 'ruby', 'java', 'xml', 'bash'}
            
            # Determine active filters
            requested_langs = set(cat for cat in show_categories if cat in valid_langs)
            # 'other' or 'others' means show non-standard web langs
            show_other_langs = 'other' in show_categories or 'others' in show_categories
            
            # If 'comment' is specified:
            # - If NO specific langs are requested AND NO 'other', show ALL.
            # - If specific langs ARE requested or 'other' is requested, apply strict filtering.
            
            has_strict_filters = bool(requested_langs) or show_other_langs
            
            for lang, comments in self.results['comments'].items():
                if comments:
                    report.append(f"  {lang.upper()}: {len(comments)} comments")
                    if should_show('comment'):
                        # Determine if this specific language should be listed based on filters
                        should_list_lang = True
                        
                        if has_strict_filters:
                            # normalization for js
                            check_lang = 'js' if lang == 'javascript' else lang
                            
                            is_requested = check_lang in requested_langs or lang in requested_langs
                            is_standard = check_lang in standard_web_langs or lang in standard_web_langs
                            
                            # If 'other' is requested, we show non-standard
                            is_other_match = show_other_langs and not is_standard
                            
                            if not (is_requested or is_other_match):
                                should_list_lang = False
                        
                        if should_list_lang:
                            for i, comment in enumerate(comments, 1):
                                report.append(f"    {i}. File: {comment['file']} (Line: {comment['line']})")
                                report.append(f"       {comment['comment'][:100]}...")
            
            # Show suspicious comments
            suspicious_comments = []
            for lang, comments in self.results['comments'].items():
                for comment in comments:
                    comment_text = comment['comment'].lower()
                    if any(kw in comment_text for kw in self.sensitive_keywords):
                        suspicious_comments.append({'lang': lang, **comment})
            
            if suspicious_comments:
                if should_show('comment') or should_show('suspicious'):
                    report.append(f"\n  ⚠️  SUSPICIOUS COMMENTS ({len(suspicious_comments)}):")
                    
                    filtered_suspicious = []
                    for comment in suspicious_comments:
                        if has_strict_filters:
                            lang = comment['lang']
                            check_lang = 'js' if lang == 'javascript' else lang
                            is_requested = check_lang in requested_langs or lang in requested_langs
                            is_standard = check_lang in standard_web_langs or lang in standard_web_langs
                            is_other_match = show_other_langs and not is_standard
                            
                            if is_requested or is_other_match:
                                filtered_suspicious.append(comment)
                        else:
                            filtered_suspicious.append(comment)
                            
                    if filtered_suspicious:
                        for i, comment in enumerate(filtered_suspicious, 1):
                            report.append(f"    {i}. File: {comment['file']}")
                            report.append(f"       Line: {comment['line']}")
                            report.append(f"       Type: {comment['lang']}")
                            report.append(f"       Preview: {comment['comment'][:100]}...")
                    elif has_strict_filters:
                        report.append(f"    (No suspicious comments found for requested languages)")
                else:
                     report.append(f"  [!] {len(suspicious_comments)} Suspicious Comments. Use '-l comment' to list.")
            elif not should_show('comment'):
                report.append(f"  [!] Use '-l comment' to see all comments.")
        
        # Decoded Strings
        total_decoded = sum(len(strings) for strings in self.results['decoded_strings'].values())
        if total_decoded > 0:
            report.append(f"\n🔓 DECODED STRINGS ({total_decoded})")
            report.append("-" * 40)
            
            for encoding_type, strings in self.results['decoded_strings'].items():
                if strings:
                    report.append(f"  {encoding_type.upper()}: {len(strings)} strings")
                    if should_show('decode'):
                        for i, string in enumerate(strings, 1):
                            report.append(f"    {i}. File: {string['file']}")
                            report.append(f"       Line: {string['line']}")
                            report.append(f"       Encoded: {string['encoded'][:50]}...")
                            report.append(f"       Decoded: {string['decoded'][:50]}...")
            if not should_show('decode'):
                report.append(f"  [!] Use '-l decode' to list decoded strings.")
        
        # Services & Versions
        if self.results['services']:
            report.append(f"\n🏗️  SERVICES & VERSIONS DETECTED")
            report.append("-" * 40)
            
            # Detected services
            if self.results['services']['detected']:
                unique_services = set(s['service'] for s in self.results['services']['detected'])
                report.append(f"  Unique Services Detected: {len(unique_services)}")
                if should_show('service'):
                    report.append(f"  Services: {', '.join(sorted(unique_services))}")
            
            # Versions
            if self.results['services']['versions']:
                report.append(f"  Versions Found: {len(self.results['services']['versions'])}")
                if should_show('service'):
                    for version in self.results['services']['versions']:
                        report.append(f"    • {version['version']} in {version['file']}")
            
            # Framework versions
            if self.results['services']['framework_versions']:
                report.append(f"  Framework Versions: {len(self.results['services']['framework_versions'])}")
                if should_show('service'):
                    for fw_version in self.results['services']['framework_versions']:
                        report.append(f"    • {fw_version['framework']} {fw_version['version']} in {fw_version['file']}")
            
            if not should_show('service'):
                 report.append(f"  [!] Use '-l service' to list services and versions.")
        
        # Secrets & Sensitive Data
        total_secrets = sum(len(secrets) for secrets in self.results['secrets'].values())
        if total_secrets > 0:
            report.append(f"\n🔐 SECRETS & SENSITIVE DATA ({total_secrets})")
            report.append("-" * 40)
            
            for secret_type, secrets in self.results['secrets'].items():
                if secrets:
                    report.append(f"  {secret_type.replace('_', ' ').title()}: {len(secrets)}")
                    if should_show('secret'):
                        for i, secret in enumerate(secrets, 1):
                            if 'email' in secret:
                                report.append(f"    {i}. Email: {secret['email']} in {secret['file']}")
                            elif 'jwt' in secret:
                                report.append(f"    {i}. JWT Token: {secret['jwt'][:30]}... in {secret['file']}")
                            elif 'ip' in secret:
                                report.append(f"    {i}. IP Address: {secret['ip']} in {secret['file']}")
                            elif 'value' in secret:
                                report.append(f"    {i}. {secret.get('key', 'Secret')}: {secret['value'][:50]}... in {secret['file']}")
            if not should_show('secret'):
                report.append(f"  [!] Use '-l secret' to list secrets.")
        
        # High Entropy Strings (Unknown Secrets)
        if self.results['entropy']['high_entropy_strings']:
            entropy_count = len(self.results['entropy']['high_entropy_strings'])
            report.append(f"\n🎲 HIGH ENTROPY STRINGS ({entropy_count})")
            report.append("-" * 40)
            report.append(f"  Potential Unknown Secrets: {entropy_count}")
            
            if should_show('entropy'):
                for i, item in enumerate(self.results['entropy']['high_entropy_strings'], 1):
                    report.append(f"    {i}. File: {item['file']} (Line: {item['line']})")
                    report.append(f"       Value: {item['value']}")
                    report.append(f"       EntropyScore: {item['entropy']}")
            else:
                report.append(f"  [!] Use '-l entropy' to list high-entropy strings.")

        # Cloud Infrastructure
        total_cloud = sum(len(items) for items in self.results['cloud'].values())
        if total_cloud > 0:
            report.append(f"\n☁️  CLOUD INFRASTRUCTURE ({total_cloud})")
            report.append("-" * 40)
            
            for cloud_type, items in self.results['cloud'].items():
                if items:
                    report.append(f"  {cloud_type.replace('_', ' ').title()}: {len(items)}")
                    if should_show('cloud'):
                        for i, item in enumerate(items, 1):
                            report.append(f"    {i}. File: {item['file']} (Line: {item['line']})")
                            report.append(f"       Type: {item['type']}")
                            report.append(f"       Value: {item['value']}")
            if not should_show('cloud'):
                report.append(f"  [!] Use '-l cloud' to list cloud resources.")

        # Vulnerabilities
        total_vulns = sum(len(vulns) for vulns in self.results['vulnerabilities'].values())
        if total_vulns > 0:
            report.append(f"\n🚨 POTENTIAL VULNERABILITIES ({total_vulns})")
            report.append("-" * 40)
            
            for vuln_type, vulns in self.results['vulnerabilities'].items():
                if vulns:
                    report.append(f"  {vuln_type.replace('_', ' ').title()}: {len(vulns)}")
                    if should_show('vuln'):
                        for i, vuln in enumerate(vulns, 1):
                            report.append(f"    {i}. File: {vuln['file']} (Line: {vuln['line']})")
                            code_snippet = vuln.get('code', vuln.get('sink', ''))
                            report.append(f"       Code: {code_snippet[:80]}...")
            if not should_show('vuln'):
                report.append(f"  [!] Use '-l vuln' to list vulnerabilities.")
        
        # Endpoints
        total_endpoints = sum(len(endpoints) for endpoints in self.results['endpoints'].values())
        if total_endpoints > 0:
            report.append(f"\n🌐 API ENDPOINTS ({total_endpoints})")
            report.append("-" * 40)
            
            # Get unique endpoints
            unique_endpoints = set()
            for endpoints in self.results['endpoints'].values():
                for endpoint in endpoints:
                    unique_endpoints.add(endpoint['endpoint'])
            
            report.append(f"  Unique Endpoints: {len(unique_endpoints)}")
            if should_show('url'):
                for i, endpoint in enumerate(list(unique_endpoints), 1):
                    report.append(f"    {i}. {endpoint}")
            else:
                report.append(f"  [!] Use '-l url' to list endpoints.")
        
        # URL Parameters
        if self.results['urls']['parameters']:
            unique_params = set(p['param'] for p in self.results['urls']['parameters'])
            report.append(f"\n🔗 URL PARAMETERS ({len(self.results['urls']['parameters'])})")
            report.append("-" * 40)
            report.append(f"  Unique Parameters: {len(unique_params)}")
            if should_show('url'):
                report.append(f"  Parameters: {', '.join(sorted(unique_params))}")
            else:
                report.append(f"  [!] Use '-l url' to list parameters.")
        
        # Storage Access
        total_storage = sum(len(storage) for storage in self.results['storage'].values())
        if total_storage > 0:
            report.append(f"\n💾 CLIENT-SIDE STORAGE ({total_storage})")
            report.append("-" * 40)
            
            for storage_type, items in self.results['storage'].items():
                if items:
                    report.append(f"  {storage_type.replace('_', ' ').title()}: {len(items)}")
                    if should_show('storage'):
                        for i, item in enumerate(items, 1):
                            report.append(f"    {i}. Key: {item['key']} in {item['file']}")
            if not should_show('storage'):
                report.append(f"  [!] Use '-l storage' to list items.")
        
        # Penetration Testing Recommendations
        report.append("\n" + "=" * 90)
        report.append("🎯 PENETRATION TESTING RECOMMENDATIONS")
        report.append("=" * 90)
        
        recommendations = []
        
        if self.results['html']['hidden_fields']:
            recommendations.append("1. Test hidden field tampering - Modify values and observe server response")
        
        if self.results['vulnerabilities']:
            recommendations.append("2. Investigate detected vulnerability patterns - Manual verification required")
        
        if self.results['secrets']:
            recommendations.append("3. Validate exposed secrets - Check if they're still active/valid")
        
        if self.results['decoded_strings']:
            recommendations.append("4. Analyze decoded strings - They may contain sensitive information or backdoors")
        
        if self.results['comments']:
            recommendations.append("5. Review all comments - Often contain credentials, debug info, or hidden functionality")
        
        if self.results['endpoints']:
            recommendations.append("6. Test all discovered endpoints - Authentication bypass, parameter tampering")
        
        if self.results['urls']['parameters']:
            recommendations.append("7. Fuzz URL parameters - SQLi, XSS, IDOR, path traversal")
        
        if self.results['services']['detected']:
            recommendations.append("8. Research known vulnerabilities for detected services/frameworks")
        
        for i, rec in enumerate(recommendations, 1):
            report.append(f"  {rec}")
        
        # Test Cases
        if show_all: # Only show test cases in full report or if specifically requested?
             # For now, let's show test cases ONLY if their specific categories are enabled or 'all' is on
             
            report.append("\n" + "=" * 90)
            report.append("🧪 SUGGESTED TEST CASES")
            report.append("=" * 90)
            
            test_cases = []
            
            # Generate test cases based on findings
            if self.results['html']['hidden_fields'] and should_show('html'):
                for field in self.results['html']['hidden_fields']:
                    test_cases.append(f"• Modify hidden field '{field['name']}' in {field['file']}")
            
            if self.results['urls']['parameters'] and should_show('url'):
                unique_params = list(set(p['param'] for p in self.results['urls']['parameters']))
                for param in unique_params:
                    test_cases.append(f"• Fuzz parameter '{param}' with SQLi/XSS payloads")
            
            if self.results['endpoints'] and (should_show('url') or should_show('endpoint')):
                endpoints = []
                for endpoint_list in self.results['endpoints'].values():
                    endpoints.extend([e['endpoint'] for e in endpoint_list])
                for endpoint in list(set(endpoints)):
                    test_cases.append(f"• Test endpoint '{endpoint}' for unauthorized access")
            
            if self.results['secrets']['jwts'] and should_show('secret'):
                test_cases.append("• Test JWT tokens for tampering/expiration bypass")
            
            if test_cases:
                for i, test in enumerate(test_cases, 1):
                    report.append(f"  {test}")
            else:
                 report.append("  [!] Use '-l all' or specific categories to see suggested test cases.")
        
        # Save to file if requested
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(report))
            print(f"\n✅ Report saved to {output_file}")
        
        return '\n'.join(report)

def main():
    parser = argparse.ArgumentParser(
        description="PARAM-HUNTER PRO: Advanced Web Vulnerability Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s login.php                       # Analyze single file
  %(prog)s -d ./webapp/                    # Analyze entire directory
  %(prog)s -d ./src/ -o pentest_report.txt # Save pentesting report
  %(prog)s -d . --verbose                  # Show detailed output
  %(prog)s --export json                   # Export results as JSON
        
Features:
  • Advanced comment detection (HTML, JS, CSS, PHP, Python, etc.)
  • Decoded string detection (Base64, URL, Hex, HTML entities)
  • Input field identification with line numbers
  • Service/version detection
  • Vulnerability pattern matching
  • Penetration testing recommendations
        """
    )
    
    parser.add_argument('target', nargs='?', help='File or directory to analyze')
    parser.add_argument('-d', '--directory', help='Directory to analyze (recursive)')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--export', choices=['json', 'csv'], help='Export format')
    parser.add_argument('--minify', action='store_true', help='Minify output')
    parser.add_argument('-l', '--list', nargs='*', help='List specific findings (e.g. html, comment, decode, secret, vuln, service, url, storage, all)')
    
    args = parser.parse_args()
    
    if not args.target and not args.directory:
        parser.print_help()
        return
    
    hunter = AdvancedParamHunter()
    
    if args.directory:
        if os.path.isdir(args.directory):
            print(f"🔍 Scanning directory: {args.directory}")
            hunter.scan_directory(args.directory)
        else:
            print(f"❌ Directory not found: {args.directory}")
            return
    elif args.target:
        if os.path.isfile(args.target):
            print(f"🔍 Analyzing file: {args.target}")
            result = hunter.analyze_file(args.target)
            if args.verbose:
                print(result)
        elif os.path.isdir(args.target):
            print(f"🔍 Scanning directory: {args.target}")
            hunter.scan_directory(args.target)
        else:
            print(f"❌ File/directory not found: {args.target}")
            return
    
    # Generate report
    report = hunter.generate_report(args.output, args.list)
    
    if not args.output or args.verbose:
        print(report)
    
    # Export if requested
    if args.export == 'json':
        export_file = args.output or 'param_hunter_pro_results.json'
        with open(export_file, 'w', encoding='utf-8') as f:
            json.dump(hunter.results, f, indent=2, default=str)
        print(f"Results exported to {export_file}")

if __name__ == '__main__':
    main()
