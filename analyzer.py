import re
import json
import logging
import ast   # Python AST
from vulnerability_rules import PHPVulnerabilityRules, JSVulnerabilityRules


class SecurityAnalyzer:
    def __init__(self):
        self.php_rules = PHPVulnerabilityRules()
        self.js_rules = JSVulnerabilityRules()
        self.logger = logging.getLogger(__name__)
    
    def analyze_code(self, code_content, file_type):
        """
        Main analysis method that dispatches to appropriate analyzer
        """
        if file_type == 'php':
            return self._analyze_php(code_content)
        elif file_type == 'js':
            return self._analyze_javascript(code_content)
        elif file_type == 'py':   # Python AST-based analyzer
            return self._analyze_python_ast(code_content)
        else:
            raise ValueError(f"Unsupported file type: {file_type}")
    
    # ---------------- PHP ----------------
    def _analyze_php(self, code_content):
        """Analyze PHP code for security vulnerabilities"""
        vulnerabilities = []
        lines = code_content.split('\n')
        
        # ✅ Regex rules
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('#'):
                continue
            
            for rule in self.php_rules.get_all_rules():
                matches = rule['pattern'].finditer(line)
                for match in matches:
                    vulnerabilities.append({
                        'type': rule['type'],
                        'severity': rule['severity'],
                        'line': line_num,
                        'column': match.start() + 1,
                        'code': line.strip(),
                        'message': rule['message'],
                        'description': rule['description'],
                        'remediation': rule['remediation'],
                        'cwe_id': rule.get('cwe_id'),
                        'owasp_category': rule.get('owasp_category')
                    })
        
        # ✅ AST-like heuristic rules
        try:
            ast_vulns = self._analyze_php_ast(code_content)
            vulnerabilities.extend(ast_vulns)
        except Exception as e:
            self.logger.warning(f"PHP AST analysis failed: {str(e)}")

        return self._generate_report(vulnerabilities, 'php')

    def _analyze_php_ast(self, code_content):
        """AST-like analysis for PHP (regex + argument inspection)"""
        vulnerabilities = []
        lines = code_content.split('\n')

        patterns = [
            {
                'pattern': re.compile(r'\b(mysqli_query|mysql_query|pg_query)\s*\((.*?)\)', re.IGNORECASE),
                'type': 'sql_injection',
                'severity': 'critical',
                'message': 'SQL query execution with possible user input',
                'description': 'Direct concatenation of user input into SQL queries can lead to SQL Injection.',
                'remediation': 'Use prepared statements with parameterized queries.',
                'cwe_id': 'CWE-89',
                'owasp_category': 'A03:2021 – Injection'
            },
            {
                'pattern': re.compile(r'\bunserialize\s*\((.*?)\)', re.IGNORECASE),
                'type': 'deserialization',
                'severity': 'high',
                'message': 'Unserialize on potentially unsafe data',
                'description': 'Unserializing untrusted input can allow object injection or RCE.',
                'remediation': 'Do not unserialize user-controlled input; use safe formats like JSON.',
                'cwe_id': 'CWE-502',
                'owasp_category': 'A08:2021 – Software and Data Integrity Failures'
            },
            {
                'pattern': re.compile(r'\b(include|require|include_once|require_once)\s*\((.*?)\)', re.IGNORECASE),
                'type': 'file_inclusion',
                'severity': 'critical',
                'message': 'File inclusion with variable path',
                'description': 'Including files dynamically using user input can cause LFI/RFI.',
                'remediation': 'Whitelist allowed includes and use absolute paths.',
                'cwe_id': 'CWE-98',
                'owasp_category': 'A03:2021 – Injection'
            },
            {
                'pattern': re.compile(r'\bmove_uploaded_file\s*\((.*?)\)', re.IGNORECASE),
                'type': 'insecure_upload',
                'severity': 'high',
                'message': 'Insecure file upload detected',
                'description': 'User-uploaded files can lead to arbitrary code execution if not validated.',
                'remediation': 'Validate file type/size, rename safely, and store outside webroot.',
                'cwe_id': 'CWE-434',
                'owasp_category': 'A03:2021 – Injection'
            },
            {
                'pattern': re.compile(r'\b(md5|sha1)\s*\((.*?)\)', re.IGNORECASE),
                'type': 'weak_crypto',
                'severity': 'medium',
                'message': 'Weak cryptographic function detected',
                'description': 'MD5/SHA1 are outdated and vulnerable to collisions.',
                'remediation': 'Use modern algorithms like SHA-256 or bcrypt/argon2 for passwords.',
                'cwe_id': 'CWE-328',
                'owasp_category': 'A02:2021 – Cryptographic Failures'
            }
        ]

        for line_num, line in enumerate(lines, 1):
            for rule in patterns:
                match = rule['pattern'].search(line)
                if match:
                    argument = match.group(1)
                    # ✅ Only flag if user input is involved
                    if re.search(r'\$_(GET|POST|REQUEST|COOKIE|FILES)', argument, re.IGNORECASE):
                        vulnerabilities.append({
                            'type': rule['type'],
                            'severity': rule['severity'],
                            'line': line_num,
                            'column': match.start() + 1,
                            'code': line.strip(),
                            'message': rule['message'],
                            'description': rule['description'],
                            'remediation': rule['remediation'],
                            'cwe_id': rule['cwe_id'],
                            'owasp_category': rule['owasp_category']
                        })
        return vulnerabilities
    
    # ---------------- JavaScript ----------------
    def _analyze_javascript(self, code_content):
        """Analyze JavaScript code (Regex + AST heuristics)"""
        vulnerabilities = []
        lines = code_content.split('\n')
        
        # Regex rules
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
                continue
            
            for rule in self.js_rules.get_all_rules():
                matches = rule['pattern'].finditer(line)
                for match in matches:
                    vulnerabilities.append({
                        'type': rule['type'],
                        'severity': rule['severity'],
                        'line': line_num,
                        'column': match.start() + 1,
                        'code': line.strip(),
                        'message': rule['message'],
                        'description': rule['description'],
                        'remediation': rule['remediation'],
                        'cwe_id': rule.get('cwe_id'),
                        'owasp_category': rule.get('owasp_category')
                    })
        
        # AST-like heuristic patterns
        try:
            ast_vulnerabilities = self._analyze_js_ast(code_content)
            vulnerabilities.extend(ast_vulnerabilities)
        except Exception as e:
            self.logger.warning(f"AST analysis failed: {str(e)}")
        
        return self._generate_report(vulnerabilities, 'js')
    
    def _analyze_js_ast(self, code_content):
        """AST-like heuristic for JavaScript (basic regex fallback)"""
        vulnerabilities = []
        lines = code_content.split('\n')
        
        eval_pattern = re.compile(r'\beval\s*\(', re.IGNORECASE)
        settimeout_pattern = re.compile(r'setTimeout\s*\(\s*["\']', re.IGNORECASE)
      
        for line_num, line in enumerate(lines, 1):
            if eval_pattern.search(line):
                vulnerabilities.append({
                    'type': 'code_injection',
                    'severity': 'critical',
                    'line': line_num,
                    'column': eval_pattern.search(line).start() + 1,
                    'code': line.strip(),
                    'message': 'Use of eval() detected',
                    'description': 'eval() executes arbitrary JS → code injection risk.',
                    'remediation': 'Avoid eval(), use JSON.parse() or safer alternatives.',
                    'cwe_id': 'CWE-94',
                    'owasp_category': 'A03:2021 – Injection'
                })
            if settimeout_pattern.search(line):
                vulnerabilities.append({
                    'type': 'code_injection',
                    'severity': 'high',
                    'line': line_num,
                    'column': settimeout_pattern.search(line).start() + 1,
                    'code': line.strip(),
                    'message': 'setTimeout with string argument detected',
                    'description': 'Using string args in setTimeout can lead to injection.',
                    'remediation': 'Use function references instead of string.',
                    'cwe_id': 'CWE-94',
                    'owasp_category': 'A03:2021 – Injection'
                })
        
        return vulnerabilities

    # ---------------- Python ----------------
    def _analyze_python_ast(self, code_content):
        """AST-based analysis for Python code"""
        vulnerabilities = []
        try:
            tree = ast.parse(code_content)
        except Exception as e:
            self.logger.warning(f"Python AST parse failed: {str(e)}")
            return vulnerabilities
        
        for node in ast.walk(tree):
            # Dangerous eval()
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "eval":
                vulnerabilities.append({
                    'type': 'code_injection',
                    'severity': 'critical',
                    'line': node.lineno,
                    'column': node.col_offset,
                    'code': "eval(...)",
                    'message': 'Use of eval() in Python detected',
                    'description': 'eval() executes arbitrary Python code.',
                    'remediation': 'Avoid eval(), use safer parsing or refactor logic.',
                    'cwe_id': 'CWE-94',
                    'owasp_category': 'A03:2021 – Injection'
                })
            # Dangerous exec()
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "exec":
                vulnerabilities.append({
                    'type': 'code_injection',
                    'severity': 'critical',
                    'line': node.lineno,
                    'column': node.col_offset,
                    'code': "exec(...)",
                    'message': 'Use of exec() in Python detected',
                    'description': 'exec() executes arbitrary Python code → RCE risk.',
                    'remediation': 'Avoid exec(), use safer alternatives.',
                    'cwe_id': 'CWE-94',
                    'owasp_category': 'A03:2021 – Injection'
                })
        
        return vulnerabilities
    
    # ---------------- Report ----------------
    def _generate_report(self, vulnerabilities, file_type):
        """Generate analysis report with scoring"""
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] += 1
            total_score += severity_weights[severity]
        
        max_possible_score = 100
        security_score = max(0, max_possible_score - total_score)
        
        return {
            'file_type': file_type,
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': severity_counts,
            'security_score': round(security_score, 2),
            'vulnerabilities': vulnerabilities,
            'analysis_summary': {
                'most_critical_issues': [v for v in vulnerabilities if v['severity'] == 'critical'][:5],
                'risk_level': self._calculate_risk_level(security_score),
                'recommendations': self._get_general_recommendations(severity_counts)
            }
        }
    
    def _calculate_risk_level(self, security_score):
        if security_score >= 80: return 'Low'
        elif security_score >= 60: return 'Medium'
        elif security_score >= 40: return 'High'
        else: return 'Critical'
    
    def _get_general_recommendations(self, severity_counts):
        recommendations = []
        if severity_counts['critical'] > 0:
            recommendations.append("Fix critical vulnerabilities immediately.")
        if severity_counts['high'] > 0:
            recommendations.append("Resolve high-severity issues quickly.")
        if severity_counts['medium'] > 0:
            recommendations.append("Review medium-severity vulnerabilities.")
        if severity_counts['low'] > 0:
            recommendations.append("Handle low-severity issues in routine maintenance.")
        if sum(severity_counts.values()) == 0:
            recommendations.append("No vulnerabilities detected. Continue secure coding.")
        
        recommendations.extend([
            "Add automated security tests in CI/CD pipeline.",
            "Do regular code reviews.",
            "Keep dependencies updated.",
            "Follow OWASP secure coding guidelines."
        ])
        return recommendations
import re
import json
import logging
import ast   # Python AST
from vulnerability_rules import PHPVulnerabilityRules, JSVulnerabilityRules
from dynamic_analyzer import DynamicAnalyzer  # ✅ Import your dynamic analyzer


class SecurityAnalyzer:
    def __init__(self):
        self.php_rules = PHPVulnerabilityRules()
        self.js_rules = JSVulnerabilityRules()
        self.logger = logging.getLogger(__name__)
        self.dynamic_analyzer = DynamicAnalyzer()  # ✅ Initialize DynamicAnalyzer
    
    def analyze_code(self, code_content, file_type):
        """
        Main analysis method that dispatches to appropriate analyzer
        """
        if file_type == 'php':
            return self._analyze_php(code_content)
        elif file_type == 'js':
            return self._analyze_javascript(code_content)
        elif file_type == 'py':   # Python AST-based analyzer
            return self._analyze_python_ast(code_content)
        else:
            raise ValueError(f"Unsupported file type: {file_type}")
    
    # ---------------- PHP ----------------
    def _analyze_php(self, code_content):
        """Analyze PHP code for security vulnerabilities"""
        vulnerabilities = []
        lines = code_content.split('\n')
        
        # ✅ Existing static analysis
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('#'):
                continue
            
            for rule in self.php_rules.get_all_rules():
                matches = rule['pattern'].finditer(line)
                for match in matches:
                    vulnerabilities.append({
                        'type': rule['type'],
                        'severity': rule['severity'],
                        'line': line_num,
                        'column': match.start() + 1,
                        'code': line.strip(),
                        'message': rule['message'],
                        'description': rule['description'],
                        'remediation': rule['remediation'],
                        'cwe_id': rule.get('cwe_id'),
                        'owasp_category': rule.get('owasp_category')
                    })
        
        # ✅ AST-like heuristic rules
        try:
            ast_vulns = self._analyze_php_ast(code_content)
            vulnerabilities.extend(ast_vulns)
        except Exception as e:
            self.logger.warning(f"PHP AST analysis failed: {str(e)}")

        # ✅ Dynamic analysis
        try:
            dynamic_vulns = self.dynamic_analyzer.analyze_php(code_content)
            vulnerabilities.extend(dynamic_vulns)
        except Exception as e:
            self.logger.warning(f"Dynamic PHP analysis failed: {str(e)}")

        return self._generate_report(vulnerabilities, 'php')
    
    # ---------------- JavaScript ----------------
    def _analyze_javascript(self, code_content):
        """Analyze JavaScript code (Regex + AST heuristics)"""
        vulnerabilities = []
        lines = code_content.split('\n')
        
        # ✅ Static analysis
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('//') or line_stripped.startswith('/*'):
                continue
            
            for rule in self.js_rules.get_all_rules():
                matches = rule['pattern'].finditer(line)
                for match in matches:
                    vulnerabilities.append({
                        'type': rule['type'],
                        'severity': rule['severity'],
                        'line': line_num,
                        'column': match.start() + 1,
                        'code': line.strip(),
                        'message': rule['message'],
                        'description': rule['description'],
                        'remediation': rule['remediation'],
                        'cwe_id': rule.get('cwe_id'),
                        'owasp_category': rule.get('owasp_category')
                    })
        
        # ✅ AST-like heuristic
        try:
            ast_vulnerabilities = self._analyze_js_ast(code_content)
            vulnerabilities.extend(ast_vulnerabilities)
        except Exception as e:
            self.logger.warning(f"AST JS analysis failed: {str(e)}")
        
        # ✅ Dynamic analysis
        try:
            dynamic_vulns = self.dynamic_analyzer.analyze_js(code_content)
            vulnerabilities.extend(dynamic_vulns)
        except Exception as e:
            self.logger.warning(f"Dynamic JS analysis failed: {str(e)}")
        
        return self._generate_report(vulnerabilities, 'js')
    
    # ---------------- Python ----------------
    def _analyze_python_ast(self, code_content):
        """AST-based analysis for Python code"""
        vulnerabilities = []
        try:
            tree = ast.parse(code_content)
        except Exception as e:
            self.logger.warning(f"Python AST parse failed: {str(e)}")
            return vulnerabilities
        
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "eval":
                vulnerabilities.append({
                    'type': 'code_injection',
                    'severity': 'critical',
                    'line': node.lineno,
                    'column': node.col_offset,
                    'code': "eval(...)",
                    'message': 'Use of eval() in Python detected',
                    'description': 'eval() executes arbitrary Python code.',
                    'remediation': 'Avoid eval(), use safer parsing or refactor logic.',
                    'cwe_id': 'CWE-94',
                    'owasp_category': 'A03:2021 – Injection'
                })
            if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "exec":
                vulnerabilities.append({
                    'type': 'code_injection',
                    'severity': 'critical',
                    'line': node.lineno,
                    'column': node.col_offset,
                    'code': "exec(...)",
                    'message': 'Use of exec() in Python detected',
                    'description': 'exec() executes arbitrary Python code → RCE risk.',
                    'remediation': 'Avoid exec(), use safer alternatives.',
                    'cwe_id': 'CWE-94',
                    'owasp_category': 'A03:2021 – Injection'
                })
        
        # 🔹 Optionally: dynamic analysis for Python can be added here later
        return self._generate_report(vulnerabilities, 'py')
    
    # ---------------- Report & helpers ----------------
    def _generate_report(self, vulnerabilities, file_type):
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 1}
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        total_score = 0
        for vuln in vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] += 1
            total_score += severity_weights[severity]
        
        max_possible_score = 100
        security_score = max(0, max_possible_score - total_score)
        
        return {
            'file_type': file_type,
            'total_vulnerabilities': len(vulnerabilities),
            'severity_counts': severity_counts,
            'security_score': round(security_score, 2),
            'vulnerabilities': vulnerabilities,
            'analysis_summary': {
                'most_critical_issues': [v for v in vulnerabilities if v['severity'] == 'critical'][:5],
                'risk_level': self._calculate_risk_level(security_score),
                'recommendations': self._get_general_recommendations(severity_counts)
            }
        }
    
    def _calculate_risk_level(self, security_score):
        if security_score >= 80: return 'Low'
        elif security_score >= 60: return 'Medium'
        elif security_score >= 40: return 'High'
        else: return 'Critical'
    
    def _get_general_recommendations(self, severity_counts):
        recommendations = []
        if severity_counts['critical'] > 0:
            recommendations.append("Fix critical vulnerabilities immediately.")
        if severity_counts['high'] > 0:
            recommendations.append("Resolve high-severity issues quickly.")
        if severity_counts['medium'] > 0:
            recommendations.append("Review medium-severity vulnerabilities.")
        if severity_counts['low'] > 0:
            recommendations.append("Handle low-severity issues in routine maintenance.")
        if sum(severity_counts.values()) == 0:
            recommendations.append("No vulnerabilities detected. Continue secure coding.")
        
        recommendations.extend([
            "Add automated security tests in CI/CD pipeline.",
            "Do regular code reviews.",
            "Keep dependencies updated.",
            "Follow OWASP secure coding guidelines."
        ])
        return recommendations
