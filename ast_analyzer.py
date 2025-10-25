# ast_analyzer.py
import os
import json
import tempfile
import subprocess
import re
from shutil import which

"""
AST Analyzer helper.

- JS: uses node + esprima (if available). Creates a temporary JS helper (esprima-based),
      runs node on the file to analyze, and parses JSON findings.

- PHP: simple dataflow heuristics implemented using regex to reduce false positives:
       finds variables assigned from superglobals and sees if those variables later
       appear as arguments to dangerous sinks.
"""

# --- JS AST helper code (esprima)
_JS_ESPRIMA_SCRIPT = r"""
// js_ast_check.js
// Usage: node js_ast_check.js <target_file.js>
// Requires: npm i esprima

const fs = require('fs');
const esprima = require('esprima');

function pushFinding(list, node, msg, type='code_injection', severity='high') {
  if (!node || !node.loc) return;
  list.push({
    type: type,
    severity: severity,
    message: msg,
    line: node.loc.start.line,
    column: node.loc.start.column + 1
  });
}

try {
  const path = process.argv[2];
  if (!path) {
    console.error(JSON.stringify({error: "no path"}));
    process.exit(1);
  }
  const code = fs.readFileSync(path, 'utf8');
  const ast = esprima.parseScript(code, {loc: true, tolerant: true});

  const findings = [];

  // simple traversal
  function walk(node) {
    if (!node) return;
    switch (node.type) {
      case 'CallExpression':
        if (node.callee && node.callee.type === 'Identifier') {
          const name = node.callee.name;
          if (name === 'eval') {
            pushFinding(findings, node, 'Use of eval() detected', 'code_injection', 'critical');
          } else if (name === 'setTimeout' || name === 'setInterval') {
            // argument is string literal?
            if (node.arguments && node.arguments.length > 0) {
              const a0 = node.arguments[0];
              if (a0.type === 'Literal' && typeof a0.value === 'string') {
                pushFinding(findings, node, name + ' called with string argument', 'code_injection', 'high');
              }
            }
          } else if (name === 'fetch') {
            // check for http literal
            if (node.arguments && node.arguments.length > 0) {
              const a0 = node.arguments[0];
              if (a0.type === 'Literal' && typeof a0.value === 'string' && a0.value.startsWith('http:')) {
                pushFinding(findings, node, 'fetch over insecure http detected', 'insecure_transport', 'medium');
              }
            }
          } else if (name === 'document' || name === 'window') {
            // skip here
          }
        }
        break;
      case 'AssignmentExpression':
        // innerHTML or outerHTML assignment
        if (node.left && node.left.type === 'MemberExpression') {
          const prop = node.left.property && (node.left.property.name || (node.left.property.value));
          if (prop === 'innerHTML' || prop === 'outerHTML') {
            pushFinding(findings, node, prop + ' assignment detected (possible DOM XSS)', 'dom_xss', 'high');
          }
        }
        break;
      case 'MemberExpression':
        // document.write detection handled in CallExpression as callee being MemberExpression
        break;
      case 'ExpressionStatement':
        if (node.expression && node.expression.type === 'CallExpression') {
          const callee = node.expression.callee;
          if (callee && callee.type === 'MemberExpression') {
            const object = callee.object;
            const prop = callee.property && (callee.property.name || callee.property.value);
            if (object && object.name === 'document' && prop === 'write') {
              pushFinding(findings, node, 'document.write() detected (possible XSS)', 'dom_xss', 'high');
            }
          }
        }
        break;
      default:
        break;
    }

    // iterate children
    for (const k in node) {
      if (!node.hasOwnProperty(k)) continue;
      const child = node[k];
      if (Array.isArray(child)) {
        for (const c of child) if (c && typeof c.type === 'string') walk(c);
      } else if (child && typeof child.type === 'string') {
        walk(child);
      }
    }
  }

  walk(ast);
  console.log(JSON.stringify({ok: true, findings: findings}));
} catch (e) {
  console.log(JSON.stringify({ok: false, error: e.message}));
}
"""

# --- Helper to run JS AST if node + esprima exist
def _node_and_esprima_available():
    node_path = which('node')
    if not node_path:
        return False
    # check esprima available
    try:
        proc = subprocess.run(['node', '-e', "require('esprima'); console.log('ok')"], capture_output=True, text=True, timeout=5)
        return proc.returncode == 0
    except Exception:
        return False


class ASTAnalyzer:
    def __init__(self):
        # create temp js helper file once on init
        self._js_helper_path = None
        self._js_helper_created = False

    def _ensure_js_helper(self):
        if self._js_helper_created and self._js_helper_path and os.path.exists(self._js_helper_path):
            return
        fd, path = tempfile.mkstemp(prefix='js_ast_helper_', suffix='.js', text=True)
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(_JS_ESPRIMA_SCRIPT)
        self._js_helper_path = path
        self._js_helper_created = True

    def analyze(self, code_content, file_type):
        findings = []
        if file_type == 'js':
            findings = self._analyze_js(code_content)
        elif file_type == 'php':
            findings = self._analyze_php_heuristic(code_content)
        return findings

    # --- JS AST analysis via node + esprima (best-effort). Returns list of vulnerability dicts.
    def _analyze_js(self, code_content):
        results = []
        if not _node_and_esprima_available():
            # Esprima not available -> fall back to no AST results (regex still runs)
            return results

        self._ensure_js_helper()

        # write temp file for target code
        tf = tempfile.NamedTemporaryFile(delete=False, suffix='.js', mode='w', encoding='utf-8')
        try:
            tf.write(code_content)
            tf.close()
            proc = subprocess.run(['node', self._js_helper_path, tf.name], capture_output=True, text=True, timeout=6)
            out = proc.stdout.strip() or proc.stderr.strip()
            if not out:
                return results
            data = json.loads(out)
            if data.get('ok'):
                for f in data.get('findings', []):
                    # map to analyzer format
                    results.append({
                        'type': f.get('type', 'ast'),
                        'severity': f.get('severity', 'medium'),
                        'line': f.get('line'),
                        'column': f.get('column'),
                        'code': None,
                        'message': f.get('message'),
                        'description': f.get('message'),
                        'remediation': 'Review the code and apply recommended mitigations (sanitize inputs, avoid dynamic execution).',
                        'cwe_id': f.get('cwe_id', None),
                        'owasp_category': f.get('owasp_category', 'A03:2021 – Injection')
                    })
            # else nothing
        except Exception:
            # fail-safe: return no ast findings
            pass
        finally:
            try:
                os.unlink(tf.name)
            except Exception:
                pass
        return results

    # --- PHP heuristic dataflow analyzer (no external dependencies)
    def _analyze_php_heuristic(self, code_content):
        """
        Lightweight heuristic:
         - Find variable names assigned from $_GET/$_POST/$_REQUEST/$_COOKIE
         - Check subsequent usage of those variables in sinks: eval, exec, include, mysql_query, etc.
         - This reduces false positives vs pure regex.
        """
        results = []
        lines = code_content.splitlines()
        # map varname -> list of line numbers where assigned from superglobals
        assigned_vars = {}

        # pattern: $var = $_GET['x']; or $var = $_POST["y"];
        assign_pattern = re.compile(r'(\$[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*)\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[\s*[\'"]([^\'"]+)[\'"]\s*\]', re.IGNORECASE)
        for i, ln in enumerate(lines, start=1):
            m = assign_pattern.search(ln)
            if m:
                var = m.group(1)
                assigned_vars.setdefault(var, []).append(i)

        # sinks: eval, system, exec, shell_exec, passthru, preg_replace /e, include/require, mysql_query, etc.
        sink_patterns = {
            'eval': re.compile(r'\beval\s*\(\s*([^;]+)\s*\)', re.IGNORECASE),
            'exec': re.compile(r'\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*([^;]+)\s*\)', re.IGNORECASE),
            'include': re.compile(r'\b(?:include|require|include_once|require_once)\s*\(\s*([^;]+)\s*\)', re.IGNORECASE),
            'mysql_query': re.compile(r'\b(?:mysql_query|mysqli_query|pg_query|sqlite_query)\s*\(\s*([^;]+)\s*\)', re.IGNORECASE),
            'unserialize': re.compile(r'\bunserialize\s*\(\s*([^;]+)\s*\)', re.IGNORECASE),
            'preg_e': re.compile(r'preg_replace\s*\(\s*([^,]+),\s*([^,]+),\s*([^,]+),\s*[\'"]e[\'"]\s*\)', re.IGNORECASE),
            'curl_exec': re.compile(r'\b(?:curl_exec|file_get_contents|fopen)\s*\(\s*([^;]+)\s*\)', re.IGNORECASE),
        }

        # For each line, check sinks and see if the expression contains any assigned var
        for i, ln in enumerate(lines, start=1):
            for sink_name, pat in sink_patterns.items():
                m = pat.search(ln)
                if m:
                    expr = m.group(1)
                    for var in assigned_vars.keys():
                        # simple containment check for variable name in the sink expression
                        if var in expr:
                            results.append({
                                'type': 'dataflow_' + sink_name,
                                'severity': 'critical' if sink_name in ('eval','exec','preg_e','unserialize') else 'high',
                                'line': i,
                                'column': ln.find(var) + 1 if ln.find(var) != -1 else None,
                                'code': ln.strip(),
                                'message': f'User-controlled variable {var} flows into {sink_name}() (possible {sink_name} injection)',
                                'description': 'This heuristic found a variable assigned from user input used in a sensitive sink. Review and sanitize inputs or use parameterized APIs.',
                                'remediation': 'Validate and sanitize user input; use prepared statements or safe APIs.',
                                'cwe_id': 'CWE-94' if sink_name in ('eval','preg_e','unserialize') else 'CWE-77',
                                'owasp_category': 'A03:2021 – Injection'
                            })
        return results
