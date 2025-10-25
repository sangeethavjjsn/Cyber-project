import subprocess
import tempfile
import os

class DynamicAnalyzer:
    def __init__(self):
        # 🔹 Payload library (can be extended easily)
        self.payloads = {
            "xss": "<script>alert(1)</script>",
            "sqli": "' OR '1'='1",
            "file_inclusion": "../../../../etc/passwd",
            "command_injection": "test; ls",
        }

    def analyze_php(self, code_content):
        vulnerabilities = []
        with tempfile.NamedTemporaryFile(delete=False, suffix=".php", mode="w") as tmp:
            tmp.write(code_content)
            tmp_path = tmp.name

        try:
            for vuln_type, payload in self.payloads.items():
                result = subprocess.run(
                    ["php", tmp_path],
                    env={**os.environ, "QUERY_STRING": f"id={payload}"},
                    capture_output=True, text=True, timeout=5
                )

                output = result.stdout + result.stderr

                # 🔹 Detection heuristics
                if payload in output:
                    vulnerabilities.append(self._build_vuln(vuln_type, payload, "Reflected in output"))
                if "SQL" in output or "syntax" in output:
                    vulnerabilities.append(self._build_vuln("sqli", payload, "SQL error message found"))
                if "root:x:" in output:
                    vulnerabilities.append(self._build_vuln("file_inclusion", payload, "/etc/passwd leaked"))
                if "command not found" in output or "bin" in output:
                    vulnerabilities.append(self._build_vuln("command_injection", payload, "Command executed"))

        except Exception as e:
            vulnerabilities.append({
                "type": "DAST_Error",
                "severity": "low",
                "message": "Dynamic PHP analysis failed",
                "description": str(e),
                "remediation": "Ensure safe runtime execution"
            })
        finally:
            os.remove(tmp_path)

        return vulnerabilities

    def analyze_js(self, code_content):
        vulnerabilities = []
        with tempfile.NamedTemporaryFile(delete=False, suffix=".js", mode="w") as tmp:
            tmp.write(code_content)
            tmp_path = tmp.name

        try:
            for vuln_type, payload in self.payloads.items():
                result = subprocess.run(
                    ["node", tmp_path],
                    input=payload.encode("utf-8"),
                    capture_output=True, timeout=5
                )
                output = result.stdout.decode() + result.stderr.decode()

                if payload in output:
                    vulnerabilities.append(self._build_vuln(vuln_type, payload, "Reflected in JS output"))

        except Exception as e:
            vulnerabilities.append({
                "type": "DAST_Error",
                "severity": "low",
                "message": "Dynamic JS analysis failed",
                "description": str(e),
                "remediation": "Ensure safe Node.js execution"
            })
        finally:
            os.remove(tmp_path)

        return vulnerabilities

    def _build_vuln(self, vuln_type, payload, detail):
        """Helper to build consistent vulnerability reports"""
        return {
            "type": vuln_type.upper(),
            "severity": "high" if vuln_type in ["sqli", "command_injection"] else "medium",
            "message": f"Dynamic {vuln_type.upper()} detected",
            "description": f"Payload `{payload}` triggered issue: {detail}",
            "remediation": "Sanitize and validate all user inputs",
            "cwe_id": "CWE-89" if vuln_type == "sqli" else "CWE-79",
            "owasp_category": "A03:2021 – Injection"
        }
