#!/usr/bin/env python3
"""
AI-powered vulnerability triage engine
Analyzes vulnerabilities for severity classification, false positive detection, and business impact assessment
"""

import json
import sys
import argparse
import re
import logging
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityFeatures:
    """Features extracted from vulnerability data"""
    title_length: int
    description_length: int
    evidence_length: int
    confidence_score: int
    has_payload: bool
    response_code: int
    parameter_count: int
    vuln_type_score: int
    url_depth: int
    is_authenticated: bool

class TriageEngine:
    """AI-powered vulnerability triage engine"""
    
    def __init__(self):
        self.severity_model = None
        self.fp_model = None
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        
        # Vulnerability type severity mappings
        self.vuln_type_severity = {
            'remote code execution': 5,
            'sql injection': 5,
            'cross-site scripting': 4,
            'server-side request forgery': 4,
            'cors misconfiguration': 3,
            'cross-site request forgery': 3,
            'local file inclusion': 4,
            'information disclosure': 2,
            'open redirect': 2,
        }
        
        # Load pre-trained models if available
        self.load_models()
    
    def load_models(self):
        """Load pre-trained ML models"""
        try:
            model_dir = os.path.join(os.path.dirname(__file__), 'models')
            if os.path.exists(os.path.join(model_dir, 'severity_model.pkl')):
                self.severity_model = joblib.load(os.path.join(model_dir, 'severity_model.pkl'))
            if os.path.exists(os.path.join(model_dir, 'fp_model.pkl')):
                self.fp_model = joblib.load(os.path.join(model_dir, 'fp_model.pkl'))
        except Exception as e:
            logger.warning(f"Could not load pre-trained models: {e}")
    
    def extract_features(self, vulnerability: Dict) -> VulnerabilityFeatures:
        """Extract features from vulnerability data"""
        return VulnerabilityFeatures(
            title_length=len(vulnerability.get('title', '')),
            description_length=len(vulnerability.get('description', '')),
            evidence_length=len(vulnerability.get('evidence', '')),
            confidence_score=vulnerability.get('confidence', 0),
            has_payload=bool(vulnerability.get('payload')),
            response_code=self.extract_response_code(vulnerability.get('evidence', '')),
            parameter_count=len(vulnerability.get('parameter', '').split(',')) if vulnerability.get('parameter') else 0,
            vuln_type_score=self.get_vuln_type_score(vulnerability.get('type', '')),
            url_depth=len(vulnerability.get('url', '').split('/')) - 3,
            is_authenticated=self.detect_authentication(vulnerability)
        )
    
    def extract_response_code(self, evidence: str) -> int:
        """Extract HTTP response code from evidence"""
        match = re.search(r'Status[:\s]+(\d{3})', evidence)
        return int(match.group(1)) if match else 200
    
    def get_vuln_type_score(self, vuln_type: str) -> int:
        """Get severity score for vulnerability type"""
        vuln_type_lower = vuln_type.lower()
        for key, score in self.vuln_type_severity.items():
            if key in vuln_type_lower:
                return score
        return 2
    
    def detect_authentication(self, vulnerability: Dict) -> bool:
        """Detect if vulnerability requires authentication"""
        indicators = ['login', 'auth', 'session', 'cookie', 'token']
        text = f"{vulnerability.get('title', '')} {vulnerability.get('description', '')}".lower()
        return any(indicator in text for indicator in indicators)
    
    def classify_severity(self, vulnerability: Dict) -> Tuple[str, float]:
        """Classify vulnerability severity using AI"""
        features = self.extract_features(vulnerability)
        
        if self.severity_model:
            # Use trained model
            feature_vector = self.features_to_vector(features)
            prediction = self.severity_model.predict([feature_vector])[0]
            confidence = max(self.severity_model.predict_proba([feature_vector])[0])
            return prediction, confidence
        else:
            # Use rule-based classification
            return self.rule_based_severity_classification(vulnerability, features)
    
    def rule_based_severity_classification(self, vulnerability: Dict, features: VulnerabilityFeatures) -> Tuple[str, float]:
        """Rule-based severity classification"""
        score = 0
        confidence = 0.7
        
        # Base score from vulnerability type
        score += features.vuln_type_score
        
        # Confidence adjustment
        if features.confidence_score > 90:
            score += 1
            confidence += 0.1
        elif features.confidence_score < 50:
            score -= 1
            confidence -= 0.2
        
        # Evidence quality
        if features.evidence_length > 100:
            score += 0.5
            confidence += 0.1
        
        # Payload presence
        if features.has_payload:
            score += 0.5
        
        # Response code analysis
        if features.response_code == 200:
            score += 0.5
        elif features.response_code >= 400:
            score -= 0.5
        
        # Authentication requirement
        if features.is_authenticated:
            score -= 0.5
        
        # Convert score to severity
        if score >= 4.5:
            return 'critical', min(confidence + 0.1, 1.0)
        elif score >= 3.5:
            return 'high', confidence
        elif score >= 2.5:
            return 'medium', confidence
        elif score >= 1.5:
            return 'low', confidence
        else:
            return 'info', confidence
    
    def detect_false_positive(self, vulnerability: Dict) -> Tuple[bool, float, str]:
        """Detect if vulnerability is a false positive"""
        if self.fp_model:
            features = self.extract_features(vulnerability)
            feature_vector = self.features_to_vector(features)
            is_fp = self.fp_model.predict([feature_vector])[0]
            confidence = max(self.fp_model.predict_proba([feature_vector])[0])
            return bool(is_fp), confidence, "ML model prediction"
        else:
            return self.rule_based_false_positive_detection(vulnerability)
    
    def rule_based_false_positive_detection(self, vulnerability: Dict) -> Tuple[bool, float, str]:
        """Rule-based false positive detection"""
        fp_indicators = [
            ('error page', lambda v: 'error' in v.get('title', '').lower() and v.get('confidence', 0) < 70),
            ('generic response', lambda v: len(v.get('evidence', '')) < 50 and 'generic' in v.get('description', '').lower()),
            ('low confidence', lambda v: v.get('confidence', 0) < 30),
            ('no evidence', lambda v: not v.get('evidence', '').strip()),
            ('timeout response', lambda v: 'timeout' in v.get('evidence', '').lower()),
        ]
        
        for reason, check in fp_indicators:
            if check(vulnerability):
                return True, 0.8, f"Rule-based detection: {reason}"
        
        return False, 0.2, "No false positive indicators found"
    
    def assess_business_impact(self, vulnerability: Dict) -> str:
        """Assess business impact of vulnerability"""
        url = vulnerability.get('url', '')
        vuln_type = vulnerability.get('type', '').lower()
        severity = vulnerability.get('severity', 'medium').lower()
        
        # Critical business functions
        critical_paths = ['/admin', '/api', '/payment', '/checkout', '/login', '/dashboard']
        is_critical_path = any(path in url.lower() for path in critical_paths)
        
        # High-impact vulnerability types
        high_impact_types = ['remote code execution', 'sql injection', 'authentication bypass']
        is_high_impact_type = any(vuln_type in vuln_type.lower() for vuln_type in high_impact_types)
        
        if severity == 'critical' and (is_critical_path or is_high_impact_type):
            return "CRITICAL: Immediate threat to core business operations. Potential for complete system compromise, data breach, or service disruption."
        elif severity == 'high' and is_critical_path:
            return "HIGH: Significant risk to important business functions. Could lead to unauthorized access to sensitive areas or data exposure."
        elif severity in ['high', 'critical']:
            return "MODERATE-HIGH: Security vulnerability that could impact business operations if exploited. Requires prompt attention."
        elif is_critical_path:
            return "MODERATE: Vulnerability in critical business path requires attention despite lower severity rating."
        else:
            return "LOW-MODERATE: Standard security vulnerability with limited direct business impact. Should be addressed in regular security maintenance."
    
    def features_to_vector(self, features: VulnerabilityFeatures) -> List[float]:
        """Convert features to vector for ML model"""
        return [
            features.title_length,
            features.description_length,
            features.evidence_length,
            features.confidence_score,
            int(features.has_payload),
            features.response_code,
            features.parameter_count,
            features.vuln_type_score,
            features.url_depth,
            int(features.is_authenticated)
        ]
    
    def generate_recommendations(self, vulnerabilities: List[Dict]) -> List[str]:
        """Generate recommendations based on vulnerability analysis"""
        recommendations = []
        
        # Count vulnerabilities by type and severity
        vuln_counts = {}
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'unknown')
            severity = vuln.get('severity', 'medium').lower()
            
            vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Priority recommendations
        if severity_counts['critical'] > 0:
            recommendations.append(f"URGENT: Address {severity_counts['critical']} critical vulnerabilities immediately")
        
        if severity_counts['high'] > 0:
            recommendations.append(f"HIGH PRIORITY: Remediate {severity_counts['high']} high-severity vulnerabilities within 24-48 hours")
        
        # Type-specific recommendations
        if 'Cross-Site Scripting' in vuln_counts:
            recommendations.append("Implement Content Security Policy (CSP) headers to mitigate XSS attacks")
        
        if 'SQL Injection' in vuln_counts:
            recommendations.append("Use parameterized queries and prepared statements for all database interactions")
        
        if 'CORS Misconfiguration' in vuln_counts:
            recommendations.append("Review and restrict CORS policy to trusted domains only")
        
        if 'Remote Code Execution' in vuln_counts:
            recommendations.append("Implement input validation and sandboxing for user-controlled data")
        
        # General recommendations
        total_vulns = sum(severity_counts.values())
        if total_vulns > 10:
            recommendations.append("Consider comprehensive security architecture review due to high vulnerability count")
        
        return recommendations

def main():
    parser = argparse.ArgumentParser(description='AI-powered vulnerability triage engine')
    parser.add_argument('--action', required=True, choices=['classify_severity', 'detect_fp', 'assess_business_impact', 'generate_recommendations'])
    parser.add_argument('--vulnerability', help='JSON string of vulnerability data')
    parser.add_argument('--vulnerabilities', help='JSON string of vulnerabilities list')
    parser.add_argument('--factors', help='JSON string of factors for business impact assessment')
    
    args = parser.parse_args()
    
    engine = TriageEngine()
    
    try:
        if args.action == 'classify_severity':
            vulnerability = json.loads(args.vulnerability)
            severity, confidence = engine.classify_severity(vulnerability)
            result = {'severity': severity, 'confidence': confidence}
            print(json.dumps(result))
        
        elif args.action == 'detect_fp':
            vulnerability = json.loads(args.vulnerability)
            is_fp, confidence, reasoning = engine.detect_false_positive(vulnerability)
            result = {
                'is_false_positive': is_fp,
                'confidence': confidence,
                'reasoning': reasoning
            }
            print(json.dumps(result))
        
        elif args.action == 'assess_business_impact':
            factors = json.loads(args.factors) if args.factors else {}
            impact = engine.assess_business_impact(factors)
            result = {'impact': impact}
            print(json.dumps(result))
        
        elif args.action == 'generate_recommendations':
            vulnerabilities = json.loads(args.vulnerabilities) if args.vulnerabilities else []
            recommendations = engine.generate_recommendations(vulnerabilities)
            result = {'recommendations': recommendations}
            print(json.dumps(result))
    
    except Exception as e:
        logger.error(f"Error processing request: {e}")
        error_result = {'error': str(e), 'success': False}
        print(json.dumps(error_result))
        sys.exit(1)

if __name__ == '__main__':
    main()
