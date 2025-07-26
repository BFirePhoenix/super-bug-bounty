#!/usr/bin/env python3
"""
AI-powered false positive filter for vulnerability assessment
Uses machine learning and rule-based approaches to identify false positives
"""

import json
import sys
import argparse
import re
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
import numpy as np

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class FilterResult:
    """Result of false positive filtering"""
    is_false_positive: bool
    confidence: float
    reasoning: str
    rules_triggered: List[str]

class FalsePositiveFilter:
    """AI-powered false positive detection system"""
    
    def __init__(self):
        self.rules = self.load_fp_rules()
        self.ml_model = None  # Placeholder for ML model
        
    def load_fp_rules(self) -> List[Dict]:
        """Load false positive detection rules"""
        return [
            {
                'name': 'generic_error_page',
                'description': 'Generic error page responses',
                'pattern': r'(?i)(404|not found|error|exception)',
                'confidence_threshold': 60,
                'weight': 0.8
            },
            {
                'name': 'no_evidence',
                'description': 'No substantial evidence provided',
                'check': lambda v: len(v.get('evidence', '').strip()) < 20,
                'weight': 0.9
            },
            {
                'name': 'low_confidence',
                'description': 'Very low confidence score',
                'check': lambda v: v.get('confidence', 100) < 30,
                'weight': 0.7
            },
            {
                'name': 'timeout_response',
                'description': 'Timeout or connection error',
                'pattern': r'(?i)(timeout|connection|refused|unreachable)',
                'weight': 0.8
            },
            {
                'name': 'generic_response',
                'description': 'Generic or templated response',
                'check': self.is_generic_response,
                'weight': 0.6
            },
            {
                'name': 'cdn_error',
                'description': 'CDN or proxy error response',
                'pattern': r'(?i)(cloudflare|cdn|proxy|gateway)',
                'response_code': [502, 503, 504],
                'weight': 0.7
            },
            {
                'name': 'false_xss_reflection',
                'description': 'XSS payload reflected but not executed',
                'vuln_type': 'xss',
                'check': self.is_false_xss_reflection,
                'weight': 0.8
            },
            {
                'name': 'sql_error_false_positive',
                'description': 'SQL error that is not actually exploitable',
                'vuln_type': 'sqli',
                'check': self.is_sql_false_positive,
                'weight': 0.7
            },
            {
                'name': 'rce_safe_command',
                'description': 'RCE with safe command output',
                'vuln_type': 'rce',
                'check': self.is_rce_safe_command,
                'weight': 0.6
            }
        ]
    
    def analyze_vulnerability(self, vulnerability: Dict) -> FilterResult:
        """Analyze vulnerability for false positive indicators"""
        triggered_rules = []
        total_weight = 0.0
        max_confidence = 0.0
        reasoning_parts = []
        
        vuln_type = vulnerability.get('type', '').lower()
        evidence = vulnerability.get('evidence', '')
        title = vulnerability.get('title', '')
        description = vulnerability.get('description', '')
        confidence = vulnerability.get('confidence', 100)
        
        # Check each rule
        for rule in self.rules:
            rule_triggered = False
            rule_confidence = 0.0
            
            # Check if rule applies to this vulnerability type
            if 'vuln_type' in rule:
                if rule['vuln_type'] not in vuln_type:
                    continue
            
            # Pattern-based rules
            if 'pattern' in rule:
                text_to_check = f"{title} {description} {evidence}"
                if re.search(rule['pattern'], text_to_check):
                    rule_triggered = True
                    rule_confidence = rule['weight']
            
            # Function-based rules
            elif 'check' in rule:
                try:
                    if rule['check'](vulnerability):
                        rule_triggered = True
                        rule_confidence = rule['weight']
                except Exception as e:
                    logger.warning(f"Rule check failed for {rule['name']}: {e}")
                    continue
            
            # Response code rules
            if 'response_code' in rule:
                response_codes = self.extract_response_codes(evidence)
                if any(code in rule['response_code'] for code in response_codes):
                    rule_triggered = True
                    rule_confidence = max(rule_confidence, rule['weight'])
            
            # Confidence threshold rules
            if 'confidence_threshold' in rule:
                if confidence < rule['confidence_threshold']:
                    rule_triggered = True
                    rule_confidence = max(rule_confidence, rule['weight'])
            
            if rule_triggered:
                triggered_rules.append(rule['name'])
                reasoning_parts.append(rule['description'])
                total_weight += rule_confidence
                max_confidence = max(max_confidence, rule_confidence)
        
        # Calculate overall false positive probability
        if not triggered_rules:
            return FilterResult(
                is_false_positive=False,
                confidence=0.1,
                reasoning="No false positive indicators detected",
                rules_triggered=[]
            )
        
        # Weighted scoring
        fp_score = min(total_weight / len(triggered_rules), 1.0)
        
        # Additional ML-based analysis (placeholder)
        if self.ml_model:
            ml_score = self.ml_predict(vulnerability)
            fp_score = (fp_score + ml_score) / 2
        
        is_fp = fp_score > 0.5
        confidence = fp_score if is_fp else 1 - fp_score
        
        reasoning = f"False positive indicators: {', '.join(reasoning_parts)}"
        
        return FilterResult(
            is_false_positive=is_fp,
            confidence=confidence,
            reasoning=reasoning,
            rules_triggered=triggered_rules
        )
    
    def is_generic_response(self, vulnerability: Dict) -> bool:
        """Check if response appears to be generic or templated"""
        evidence = vulnerability.get('evidence', '').lower()
        
        generic_indicators = [
            'default page',
            'coming soon',
            'under construction',
            'placeholder',
            'lorem ipsum',
            'test page',
            'hello world',
            'it works'
        ]
        
        return any(indicator in evidence for indicator in generic_indicators)
    
    def is_false_xss_reflection(self, vulnerability: Dict) -> bool:
        """Check if XSS payload is reflected but not executable"""
        evidence = vulnerability.get('evidence', '')
        payload = vulnerability.get('payload', '')
        
        if not payload:
            return False
        
        # Check if payload is reflected
        if payload not in evidence:
            return True  # Not even reflected
        
        # Check if payload appears in non-executable context
        non_executable_contexts = [
            f'<!-- {payload} -->',  # HTML comment
            f'&lt;{payload}&gt;',   # HTML encoded
            f'\\{payload}',         # Escaped
        ]
        
        for context in non_executable_contexts:
            if context in evidence:
                return True
        
        # Check if within text content (not attributes or script)
        if re.search(f'>[^<]*{re.escape(payload)}[^<]*<', evidence):
            return True
        
        return False
    
    def is_sql_false_positive(self, vulnerability: Dict) -> bool:
        """Check if SQL injection is a false positive"""
        evidence = vulnerability.get('evidence', '').lower()
        
        # Check for actual SQL errors vs generic errors
        sql_error_patterns = [
            r'sql syntax.*error',
            r'mysql_fetch_array',
            r'ora-\d{5}',
            r'microsoft.*odbc.*driver',
            r'postgresql.*error'
        ]
        
        has_sql_error = any(re.search(pattern, evidence) for pattern in sql_error_patterns)
        
        # If no SQL-specific errors, likely false positive
        if not has_sql_error and ('error' in evidence or 'exception' in evidence):
            return True
        
        # Check for generic 500 errors without SQL context
        if '500' in evidence and not has_sql_error:
            return True
        
        return False
    
    def is_rce_safe_command(self, vulnerability: Dict) -> bool:
        """Check if RCE command output is from safe testing"""
        evidence = vulnerability.get('evidence', '')
        payload = vulnerability.get('payload', '')
        
        # Safe testing indicators
        safe_indicators = [
            'rce_test_',
            'test_command',
            'whoami',
            'echo test',
            'pwd'
        ]
        
        # Check if evidence contains safe command output
        evidence_lower = evidence.lower()
        payload_lower = payload.lower()
        
        if any(indicator in evidence_lower or indicator in payload_lower 
               for indicator in safe_indicators):
            # Verify it's actually command output, not just reflection
            if 'uid=' in evidence or 'gid=' in evidence:
                return False  # Real command execution
            if evidence.count('\n') > 3:  # Multi-line output suggests real execution
                return False
            return True
        
        return False
    
    def extract_response_codes(self, evidence: str) -> List[int]:
        """Extract HTTP response codes from evidence"""
        codes = []
        patterns = [
            r'status[:\s]+(\d{3})',
            r'http[/\s]+\d+\.\d+\s+(\d{3})',
            r'response[:\s]+(\d{3})'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, evidence, re.IGNORECASE)
            codes.extend([int(match) for match in matches])
        
        return codes
    
    def ml_predict(self, vulnerability: Dict) -> float:
        """Placeholder for ML model prediction"""
        # In production, this would use a trained ML model
        # For now, return based on simple heuristics
        
        features = self.extract_ml_features(vulnerability)
        
        # Simple heuristic scoring
        score = 0.0
        
        if features['evidence_length'] < 50:
            score += 0.3
        if features['confidence'] < 50:
            score += 0.4
        if features['generic_words'] > 2:
            score += 0.2
        if not features['has_payload']:
            score += 0.1
        
        return min(score, 1.0)
    
    def extract_ml_features(self, vulnerability: Dict) -> Dict:
        """Extract features for ML model"""
        evidence = vulnerability.get('evidence', '')
        title = vulnerability.get('title', '')
        description = vulnerability.get('description', '')
        
        generic_words = ['error', 'exception', 'test', 'default', 'generic']
        
        return {
            'evidence_length': len(evidence),
            'title_length': len(title),
            'description_length': len(description),
            'confidence': vulnerability.get('confidence', 100),
            'has_payload': bool(vulnerability.get('payload')),
            'generic_words': sum(1 for word in generic_words 
                               if word in evidence.lower() or word in title.lower()),
            'response_codes': len(self.extract_response_codes(evidence)),
        }
    
    def batch_filter(self, vulnerabilities: List[Dict]) -> List[FilterResult]:
        """Filter multiple vulnerabilities"""
        results = []
        for vuln in vulnerabilities:
            result = self.analyze_vulnerability(vuln)
            results.append(result)
        return results
    
    def get_statistics(self, results: List[FilterResult]) -> Dict:
        """Get filtering statistics"""
        total = len(results)
        false_positives = sum(1 for r in results if r.is_false_positive)
        
        avg_confidence = np.mean([r.confidence for r in results]) if results else 0
        
        rule_counts = {}
        for result in results:
            for rule in result.rules_triggered:
                rule_counts[rule] = rule_counts.get(rule, 0) + 1
        
        return {
            'total_analyzed': total,
            'false_positives_detected': false_positives,
            'false_positive_rate': false_positives / total if total > 0 else 0,
            'average_confidence': avg_confidence,
            'most_triggered_rules': sorted(rule_counts.items(), 
                                         key=lambda x: x[1], reverse=True)[:5]
        }

def main():
    parser = argparse.ArgumentParser(description='AI-powered false positive filter')
    parser.add_argument('--vulnerability', help='JSON string of vulnerability data')
    parser.add_argument('--vulnerabilities', help='JSON string of vulnerabilities list')
    parser.add_argument('--stats', action='store_true', help='Return statistics')
    
    args = parser.parse_args()
    
    filter_engine = FalsePositiveFilter()
    
    try:
        if args.vulnerability:
            vulnerability = json.loads(args.vulnerability)
            result = filter_engine.analyze_vulnerability(vulnerability)
            
            output = {
                'is_false_positive': result.is_false_positive,
                'confidence': result.confidence,
                'reasoning': result.reasoning,
                'rules_triggered': result.rules_triggered
            }
            print(json.dumps(output))
        
        elif args.vulnerabilities:
            vulnerabilities = json.loads(args.vulnerabilities)
            results = filter_engine.batch_filter(vulnerabilities)
            
            if args.stats:
                stats = filter_engine.get_statistics(results)
                print(json.dumps(stats))
            else:
                output = []
                for i, result in enumerate(results):
                    output.append({
                        'index': i,
                        'is_false_positive': result.is_false_positive,
                        'confidence': result.confidence,
                        'reasoning': result.reasoning,
                        'rules_triggered': result.rules_triggered
                    })
                print(json.dumps(output))
    
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        error_result = {'error': str(e), 'success': False}
        print(json.dumps(error_result))
        sys.exit(1)

if __name__ == '__main__':
    main()
