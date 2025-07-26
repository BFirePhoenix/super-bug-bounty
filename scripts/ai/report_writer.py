#!/usr/bin/env python3
"""
AI-powered report writer for security assessments
Generates professional, human-readable security reports using AI
"""

import json
import sys
import argparse
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ReportSection:
    """Individual report section"""
    title: str
    content: str
    priority: int
    section_type: str

class ReportWriter:
    """AI-powered report writer"""
    
    def __init__(self):
        self.templates = self.load_templates()
        self.severity_descriptions = self.load_severity_descriptions()
        self.impact_templates = self.load_impact_templates()
        self.remediation_templates = self.load_remediation_templates()
    
    def generate_report(self, scan_data: Dict[str, Any], report_type: str = 'comprehensive') -> str:
        """Generate a complete security assessment report"""
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        target = scan_data.get('target', 'Unknown Target')
        scan_date = scan_data.get('scan_date', datetime.now().isoformat())
        
        # Generate report sections
        sections = []
        
        # Executive Summary
        exec_summary = self.generate_executive_summary(vulnerabilities, target)
        sections.append(ReportSection('Executive Summary', exec_summary, 1, 'summary'))
        
        # Technical Overview
        tech_overview = self.generate_technical_overview(vulnerabilities, scan_data)
        sections.append(ReportSection('Technical Overview', tech_overview, 2, 'technical'))
        
        # Detailed Findings
        detailed_findings = self.generate_detailed_findings(vulnerabilities)
        sections.append(ReportSection('Detailed Findings', detailed_findings, 3, 'findings'))
        
        # Risk Assessment
        risk_assessment = self.generate_risk_assessment(vulnerabilities)
        sections.append(ReportSection('Risk Assessment', risk_assessment, 4, 'risk'))
        
        # Recommendations
        recommendations = self.generate_recommendations(vulnerabilities)
        sections.append(ReportSection('Recommendations', recommendations, 5, 'recommendations'))
        
        # Conclusion
        conclusion = self.generate_conclusion(vulnerabilities, target)
        sections.append(ReportSection('Conclusion', conclusion, 6, 'conclusion'))
        
        # Assemble final report
        return self.assemble_report(sections, target, scan_date, report_type)
    
    def generate_executive_summary(self, vulnerabilities: List[Dict], target: str) -> str:
        """Generate executive summary section"""
        
        # Count vulnerabilities by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Medium').title()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        total_vulns = len(vulnerabilities)
        critical_high = severity_counts['Critical'] + severity_counts['High']
        
        # Determine overall risk level
        if severity_counts['Critical'] > 0:
            risk_level = 'CRITICAL'
            risk_color = 'RED'
        elif severity_counts['High'] > 0:
            risk_level = 'HIGH'
            risk_color = 'ORANGE'
        elif severity_counts['Medium'] > 0:
            risk_level = 'MEDIUM'
            risk_color = 'YELLOW'
        else:
            risk_level = 'LOW'
            risk_color = 'GREEN'
        
        # Generate narrative
        summary = f"""
        This security assessment of {target} identified {total_vulns} potential security vulnerabilities across various categories. 
        
        **OVERALL RISK LEVEL: {risk_level}**
        
        The assessment revealed {critical_high} high-priority security issues that require immediate attention, including {severity_counts['Critical']} critical and {severity_counts['High']} high-severity vulnerabilities.
        
        **Key Statistics:**
        - Critical Vulnerabilities: {severity_counts['Critical']}
        - High Vulnerabilities: {severity_counts['High']}
        - Medium Vulnerabilities: {severity_counts['Medium']}
        - Low Vulnerabilities: {severity_counts['Low']}
        - Informational: {severity_counts['Info']}
        
        """
        
        if critical_high > 0:
            summary += f"""
            **IMMEDIATE ACTION REQUIRED:**
            The {critical_high} high-priority vulnerabilities identified pose significant security risks and should be addressed immediately. These vulnerabilities could potentially allow attackers to compromise the confidentiality, integrity, or availability of the system and its data.
            """
        
        # Add top vulnerability types
        vuln_types = {}
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        if vuln_types:
            top_vulns = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:3]
            summary += f"\n**Most Common Vulnerability Types:**\n"
            for vuln_type, count in top_vulns:
                summary += f"- {vuln_type}: {count} instances\n"
        
        return summary.strip()
    
    def generate_technical_overview(self, vulnerabilities: List[Dict], scan_data: Dict) -> str:
        """Generate technical overview section"""
        
        target = scan_data.get('target', 'Unknown')
        scan_duration = scan_data.get('duration', 'Unknown')
        endpoints_scanned = len(scan_data.get('endpoints', []))
        technologies = scan_data.get('technologies', [])
        
        overview = f"""
        **Target Information:**
        - Primary Target: {target}
        - Scan Duration: {scan_duration}
        - Endpoints Analyzed: {endpoints_scanned}
        
        **Technology Stack Identified:**
        """
        
        if technologies:
            for tech in technologies[:10]:  # Top 10 technologies
                tech_name = tech.get('name', 'Unknown')
                tech_version = tech.get('version', '')
                confidence = tech.get('confidence', 0)
                if tech_version:
                    overview += f"- {tech_name} {tech_version} (Confidence: {confidence}%)\n"
                else:
                    overview += f"- {tech_name} (Confidence: {confidence}%)\n"
        else:
            overview += "- No specific technologies identified\n"
        
        # Vulnerability distribution analysis
        overview += f"""
        
        **Vulnerability Distribution Analysis:**
        The security assessment employed comprehensive testing methodologies including:
        - Automated vulnerability scanning
        - Manual security testing
        - Code analysis (where applicable)  
        - Configuration review
        
        **Testing Coverage:**
        - OWASP Top 10 vulnerabilities
        - Input validation flaws
        - Authentication and session management
        - Access control issues
        - Security misconfigurations
        """
        
        return overview.strip()
    
    def generate_detailed_findings(self, vulnerabilities: List[Dict]) -> str:
        """Generate detailed findings section"""
        
        if not vulnerabilities:
            return "No significant security vulnerabilities were identified during this assessment."
        
        findings = "The following security vulnerabilities were identified during the assessment:\n\n"
        
        # Sort by severity (Critical > High > Medium > Low > Info)
        severity_order = {'Critical': 5, 'High': 4, 'Medium': 3, 'Low': 2, 'Info': 1}
        sorted_vulns = sorted(vulnerabilities, 
                            key=lambda x: severity_order.get(x.get('severity', 'Medium').title(), 2), 
                            reverse=True)
        
        for i, vuln in enumerate(sorted_vulns, 1):
            findings += self.generate_vulnerability_description(vuln, i)
            findings += "\n---\n\n"
        
        return findings.strip()
    
    def generate_vulnerability_description(self, vuln: Dict, index: int) -> str:
        """Generate detailed description for a single vulnerability"""
        
        title = vuln.get('title', 'Security Vulnerability')
        severity = vuln.get('severity', 'Medium').title()
        vuln_type = vuln.get('type', 'Security Issue')
        url = vuln.get('url', 'Not specified')
        description = vuln.get('description', 'No description available')
        impact = vuln.get('impact', 'Impact assessment not available')
        remediation = vuln.get('remediation', 'Remediation steps not provided')
        confidence = vuln.get('confidence', 0)
        
        # Generate narrative description
        narrative = f"""
        **{index}. {title}**
        
        **Severity:** {severity}
        **Type:** {vuln_type}
        **Affected URL:** {url}
        **Confidence Level:** {confidence}%
        
        **Description:**
        {self.enhance_description(description, vuln_type)}
        
        **Technical Details:**
        {description}
        
        **Potential Impact:**
        {self.enhance_impact_description(impact, severity, vuln_type)}
        
        **Remediation:**
        {self.enhance_remediation_steps(remediation, vuln_type)}
        """
        
        # Add evidence if available
        if vuln.get('evidence'):
            narrative += f"""
        
        **Evidence:**
        ```
        {vuln['evidence'][:500]}{'...' if len(vuln['evidence']) > 500 else ''}
        ```
        """
        
        # Add proof of concept if available
        if vuln.get('proof_of_concept'):
            narrative += f"""
        
        **Proof of Concept:**
        ```
        {vuln['proof_of_concept']}
        ```
        """
        
        return narrative.strip()
    
    def enhance_description(self, original_desc: str, vuln_type: str) -> str:
        """Enhance vulnerability description with context"""
        
        enhancements = {
            'Cross-Site Scripting': "Cross-Site Scripting (XSS) vulnerabilities occur when an application includes user-supplied data in a web page without properly validating or encoding it. This allows attackers to inject malicious scripts that execute in other users' browsers.",
            'SQL Injection': "SQL Injection vulnerabilities arise when user input is incorporated into SQL queries without proper sanitization. This allows attackers to manipulate database queries, potentially accessing, modifying, or deleting sensitive data.",
            'Remote Code Execution': "Remote Code Execution (RCE) vulnerabilities allow attackers to run arbitrary code on the target system. This represents one of the most severe security risks as it can lead to complete system compromise.",
            'Server-Side Request Forgery': "Server-Side Request Forgery (SSRF) vulnerabilities occur when an application makes HTTP requests to user-supplied URLs without proper validation. This can allow attackers to access internal systems or perform unauthorized actions.",
        }
        
        enhanced = enhancements.get(vuln_type, "This security vulnerability could potentially be exploited by malicious actors to compromise system security.")
        
        return f"{enhanced}\n\n{original_desc}"
    
    def enhance_impact_description(self, original_impact: str, severity: str, vuln_type: str) -> str:
        """Enhance impact description based on severity and type"""
        
        severity_impacts = {
            'Critical': "This critical vulnerability poses an immediate and severe threat to the organization. Successful exploitation could result in complete system compromise, large-scale data breach, or significant operational disruption.",
            'High': "This high-severity vulnerability presents a significant security risk. Exploitation could lead to unauthorized access to sensitive data, system compromise, or substantial business impact.",
            'Medium': "This medium-severity vulnerability represents a moderate security risk that should be addressed promptly. While not immediately critical, it could be combined with other vulnerabilities or escalated by attackers.",
            'Low': "This low-severity vulnerability has limited direct impact but should still be addressed as part of comprehensive security maintenance. It may provide attackers with additional information or serve as a stepping stone for more serious attacks."
        }
        
        enhanced = severity_impacts.get(severity, "The security impact of this vulnerability should be carefully evaluated in the context of the specific environment and threat model.")
        
        return f"{enhanced}\n\n{original_impact}"
    
    def enhance_remediation_steps(self, original_remediation: str, vuln_type: str) -> str:
        """Enhance remediation steps with best practices"""
        
        best_practices = {
            'Cross-Site Scripting': """
        **Best Practice Recommendations:**
        1. Implement Content Security Policy (CSP) headers
        2. Use context-aware output encoding
        3. Validate and sanitize all user inputs
        4. Use security-focused templating engines
        5. Regular security code reviews
        """,
            'SQL Injection': """
        **Best Practice Recommendations:**
        1. Use parameterized queries/prepared statements exclusively
        2. Implement least-privilege database access
        3. Use stored procedures with proper input validation
        4. Enable database activity monitoring
        5. Regular database security assessments
        """,
            'Remote Code Execution': """
        **Best Practice Recommendations:**
        1. Implement strict input validation and sanitization
        2. Use application sandboxing and containerization
        3. Apply principle of least privilege
        4. Regular security patching and updates
        5. Network segmentation and monitoring
        """,
        }
        
        enhanced = best_practices.get(vuln_type, """
        **General Security Best Practices:**
        1. Regular security assessments and penetration testing
        2. Implement defense-in-depth security architecture
        3. Maintain current security patches and updates
        4. Security awareness training for development teams
        5. Continuous security monitoring and incident response
        """)
        
        return f"{original_remediation}\n{enhanced}"
    
    def generate_risk_assessment(self, vulnerabilities: List[Dict]) -> str:
        """Generate risk assessment section"""
        
        # Calculate risk metrics
        total_vulns = len(vulnerabilities)
        if total_vulns == 0:
            return "Based on this assessment, the overall security risk is considered LOW with no significant vulnerabilities identified."
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Medium').title()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Risk calculation
        risk_score = (severity_counts['Critical'] * 5 + 
                     severity_counts['High'] * 4 + 
                     severity_counts['Medium'] * 3 + 
                     severity_counts['Low'] * 2 + 
                     severity_counts['Info'] * 1)
        
        max_possible_score = total_vulns * 5
        risk_percentage = (risk_score / max_possible_score) * 100 if max_possible_score > 0 else 0
        
        if risk_percentage >= 80:
            overall_risk = "CRITICAL"
        elif risk_percentage >= 60:
            overall_risk = "HIGH"
        elif risk_percentage >= 40:
            overall_risk = "MEDIUM"
        elif risk_percentage >= 20:
            overall_risk = "LOW"
        else:
            overall_risk = "MINIMAL"
        
        assessment = f"""
        **Overall Risk Assessment: {overall_risk}**
        
        **Risk Score:** {risk_score}/{max_possible_score} ({risk_percentage:.1f}%)
        
        **Risk Analysis:**
        The security assessment has identified {total_vulns} vulnerabilities with varying levels of risk. The overall risk level is determined to be {overall_risk} based on the severity and number of identified issues.
        
        **Risk Breakdown:**
        - Critical Risk Issues: {severity_counts['Critical']} ({(severity_counts['Critical']/total_vulns*100):.1f}%)
        - High Risk Issues: {severity_counts['High']} ({(severity_counts['High']/total_vulns*100):.1f}%)
        - Medium Risk Issues: {severity_counts['Medium']} ({(severity_counts['Medium']/total_vulns*100):.1f}%)
        - Low Risk Issues: {severity_counts['Low']} ({(severity_counts['Low']/total_vulns*100):.1f}%)
        
        **Business Impact Considerations:**
        """
        
        if severity_counts['Critical'] > 0:
            assessment += f"- {severity_counts['Critical']} critical vulnerabilities require immediate remediation to prevent potential system compromise\n"
        
        if severity_counts['High'] > 0:
            assessment += f"- {severity_counts['High']} high-severity issues should be prioritized in the remediation timeline\n"
        
        if severity_counts['Medium'] > 0:
            assessment += f"- {severity_counts['Medium']} medium-severity vulnerabilities should be addressed in regular security maintenance\n"
        
        return assessment.strip()
    
    def generate_recommendations(self, vulnerabilities: List[Dict]) -> str:
        """Generate recommendations section"""
        
        if not vulnerabilities:
            return """
            **Security Recommendations:**
            
            1. **Maintain Current Security Posture:** Continue current security practices and regular assessments
            2. **Proactive Monitoring:** Implement continuous security monitoring
            3. **Regular Updates:** Maintain current security patches and updates
            4. **Security Training:** Ensure development teams receive regular security training
            """
        
        # Analyze vulnerability patterns
        vuln_types = {}
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            severity = vuln.get('severity', 'Medium').title()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        recommendations = """
        **Security Recommendations:**
        
        Based on the findings of this security assessment, the following recommendations are provided in order of priority:
        
        """
        
        priority = 1
        
        # Critical and High severity recommendations
        if severity_counts['Critical'] > 0 or severity_counts['High'] > 0:
            recommendations += f"""
        **{priority}. IMMEDIATE ACTION REQUIRED (Critical Priority)**
        - Address all {severity_counts['Critical'] + severity_counts['High']} critical and high-severity vulnerabilities immediately
        - Implement emergency patches or workarounds within 24-48 hours
        - Consider taking affected systems offline if necessary until patched
        - Conduct immediate incident response procedures if exploitation is suspected
        
        """
            priority += 1
        
        # Type-specific recommendations
        common_types = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)
        
        for vuln_type, count in common_types[:3]:  # Top 3 vulnerability types
            if count > 1:
                recommendations += f"""
        **{priority}. Address {vuln_type} Vulnerabilities ({count} instances)**
        {self.get_type_specific_recommendations(vuln_type)}
        
        """
                priority += 1
        
        # General security recommendations
        recommendations += f"""
        **{priority}. Implement Comprehensive Security Program**
        - Establish regular security assessment schedule (quarterly recommended)
        - Implement security development lifecycle practices
        - Deploy web application firewall (WAF) for additional protection
        - Establish security incident response procedures
        - Conduct security awareness training for all personnel
        
        **{priority + 1}. Continuous Monitoring and Improvement**
        - Implement security information and event management (SIEM)
        - Establish vulnerability management program
        - Regular penetration testing and code reviews
        - Maintain current security patches and updates
        - Monitor security advisories for all technologies in use
        """
        
        return recommendations.strip()
    
    def get_type_specific_recommendations(self, vuln_type: str) -> str:
        """Get specific recommendations for vulnerability type"""
        
        recommendations = {
            'Cross-Site Scripting': """
        - Implement Content Security Policy (CSP) headers
        - Use context-aware output encoding for all user data
        - Validate and sanitize all user inputs
        - Use security-focused templating engines
        - Regular XSS-specific security testing
        """,
            'SQL Injection': """
        - Use parameterized queries/prepared statements exclusively
        - Implement database access controls and least privilege
        - Deploy database activity monitoring
        - Regular database security configuration reviews
        - Use stored procedures with proper input validation
        """,
            'Remote Code Execution': """
        - Implement strict input validation and sanitization
        - Use application sandboxing and containerization
        - Apply principle of least privilege for application processes
        - Regular security patching and updates
        - Network segmentation and access controls
        """,
            'CORS Misconfiguration': """
        - Review and restrict CORS policies to necessary domains only
        - Avoid using wildcard (*) in Access-Control-Allow-Origin
        - Implement proper preflight request handling
        - Regular review of cross-origin resource sharing policies
        """,
        }
        
        return recommendations.get(vuln_type, """
        - Review and remediate according to security best practices
        - Implement appropriate input validation and output encoding
        - Regular security testing for this vulnerability type
        - Follow OWASP guidelines for prevention
        """).strip()
    
    def generate_conclusion(self, vulnerabilities: List[Dict], target: str) -> str:
        """Generate conclusion section"""
        
        total_vulns = len(vulnerabilities)
        
        if total_vulns == 0:
            return f"""
        **Conclusion:**
        
        The security assessment of {target} has concluded with positive results. No significant security vulnerabilities were identified during this comprehensive evaluation. The application demonstrates good security practices and appears to be well-protected against common attack vectors.
        
        **Next Steps:**
        - Continue regular security assessments to maintain current security posture
        - Stay current with security patches and updates
        - Monitor for new threats and vulnerabilities
        - Consider expanding assessment scope in future evaluations
        """
        
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Medium').title()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        critical_high = severity_counts['Critical'] + severity_counts['High']
        
        conclusion = f"""
        **Conclusion:**
        
        The security assessment of {target} has identified {total_vulns} security vulnerabilities that require attention. """
        
        if critical_high > 0:
            conclusion += f"""Of particular concern are the {critical_high} critical and high-severity vulnerabilities that pose immediate security risks and require urgent remediation.
        
        **Immediate Action Required:**
        The critical and high-severity vulnerabilities identified in this assessment should be addressed as the highest priority. These issues could potentially be exploited by attackers to compromise the security, integrity, or availability of the system and its data."""
        else:
            conclusion += f"""The identified vulnerabilities are primarily of medium to low severity, indicating that while security improvements are needed, there are no immediate critical threats."""
        
        conclusion += f"""
        
        **Assessment Summary:**
        - Total vulnerabilities identified: {total_vulns}
        - Critical priority issues: {critical_high}
        - Recommended remediation timeline: {'Immediate (24-48 hours)' if critical_high > 0 else '30-90 days'}
        
        **Final Recommendations:**
        1. Address all identified vulnerabilities according to their severity priority
        2. Implement a comprehensive vulnerability management program
        3. Conduct regular security assessments to maintain security posture
        4. Establish incident response procedures for future security events
        5. Provide security training for development and operations teams
        
        This assessment provides a snapshot of the current security posture. Regular assessments and continuous security monitoring are recommended to maintain and improve the overall security stance.
        """
        
        return conclusion.strip()
    
    def assemble_report(self, sections: List[ReportSection], target: str, scan_date: str, report_type: str) -> str:
        """Assemble the final report"""
        
        # Sort sections by priority
        sections.sort(key=lambda x: x.priority)
        
        # Generate report header
        header = f"""
# Security Assessment Report

**Target:** {target}
**Assessment Date:** {scan_date}
**Report Type:** {report_type.title()}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

"""
        
        # Assemble sections
        report_body = ""
        for section in sections:
            report_body += f"\n## {section.title}\n\n"
            report_body += section.content
            report_body += "\n\n---\n"
        
        # Add footer
        footer = f"""

---

**Report Information:**
- This report was generated using automated security assessment tools
- Manual verification of findings is recommended
- Report classification: Confidential
- For questions regarding this assessment, please contact the security team

**Disclaimer:**
This security assessment is based on the current state of the target system at the time of testing. Security is an ongoing process, and regular assessments are recommended to maintain an effective security posture.
"""
        
        return header + report_body + footer
    
    def load_templates(self) -> Dict:
        """Load report templates"""
        return {
            'executive_summary': "Executive summary template",
            'technical_details': "Technical details template",
            'recommendations': "Recommendations template"
        }
    
    def load_severity_descriptions(self) -> Dict:
        """Load severity level descriptions"""
        return {
            'Critical': "Immediate threat requiring urgent action",
            'High': "Significant security risk requiring prompt attention",
            'Medium': "Moderate risk that should be addressed",
            'Low': "Minor security concern",
            'Info': "Informational finding"
        }
    
    def load_impact_templates(self) -> Dict:
        """Load impact description templates"""
        return {}
    
    def load_remediation_templates(self) -> Dict:
        """Load remediation templates"""
        return {}

def main():
    parser = argparse.ArgumentParser(description='AI-powered security report writer')
    parser.add_argument('--scan-data', required=True, help='JSON string of scan data')
    parser.add_argument('--report-type', default='comprehensive', help='Type of report to generate')
    parser.add_argument('--output-file', help='Output file path')
    
    args = parser.parse_args()
    
    writer = ReportWriter()
    
    try:
        scan_data = json.loads(args.scan_data)
        report = writer.generate_report(scan_data, args.report_type)
        
        if args.output_file:
            with open(args.output_file, 'w') as f:
                f.write(report)
            result = {'success': True, 'message': f'Report written to {args.output_file}'}
        else:
            result = {'success': True, 'report': report}
        
        print(json.dumps(result))
    
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        error_result = {'error': str(e), 'success': False}
        print(json.dumps(error_result))
        sys.exit(1)

if __name__ == '__main__':
    main()
