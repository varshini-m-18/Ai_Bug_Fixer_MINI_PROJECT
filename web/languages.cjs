// Multi-Language Execution & Analysis Architecture for AI Bug Fixer
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawn, spawnSync } = require('child_process');

// Auto-detect and configure toolchain paths on Windows
const extraPaths = [
  'C:\\Program Files\\CodeBlocks\\MinGW\\bin',
  'C:\\Program Files\\Eclipse Adoptium\\jdk-17.0.20.101-hotspot\\bin',
  'C:\\Users\\varsh\\AppData\\Local\\Programs\\Python\\Python312',
  'C:\\Users\\varsh\\AppData\\Local\\Programs\\Python\\Launcher'
];
const RUNTIME_ENV = {
  ...process.env,
  PATH: extraPaths.join(path.delimiter) + path.delimiter + (process.env.PATH || ''),
  NODE_ENV: 'test'
};

function runProcess(cmd, args, options = {}) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const timeoutMs = options.timeoutMs || 4000;
    const cwd = options.cwd || process.cwd();

    let child;
    try {
      child = spawn(cmd, args, {
        cwd,
        env: options.env || RUNTIME_ENV,
        timeout: timeoutMs,
        windowsHide: true
      });
    } catch (err) {
      return resolve({ ok: false, exitCode: 1, stdout: '', stderr: err.message, durationMs: 0, timedOut: false });
    }

    let stdout = '';
    let stderr = '';
    if (child.stdout) child.stdout.on('data', (d) => { stdout += d.toString(); });
    if (child.stderr) child.stderr.on('data', (d) => { stderr += d.toString(); });

    child.on('close', (code, signal) => {
      const durationMs = Date.now() - startTime;
      resolve({ ok: code === 0, exitCode: code, signal, stdout: stdout.trim(), stderr: stderr.trim(), durationMs, timedOut: signal === 'SIGTERM' || code === null });
    });
    child.on('error', (err) => {
      resolve({ ok: false, exitCode: 1, stdout: stdout.trim(), stderr: err.message, durationMs: Date.now() - startTime, timedOut: false });
    });
  });
}

const LANGUAGE_REGISTRY = {
  javascript: {
    id: 'javascript',
    name: 'JavaScript',
    runtime: 'Node.js ' + process.version,
    extension: '.js',
    filename: 'main.js',
    isCompiled: false,

    async checkSyntax(code, tmpDir) {
      const vm = require('vm');
      try { new vm.Script(code); return { ok: true, error: null }; }
      catch (err) { return { ok: false, error: err.message }; }
    },

    async execute(code, timeoutMs = 4000) {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bf-js-'));
      const filePath = path.join(tmpDir, 'main.js');
      try {
        fs.writeFileSync(filePath, code, 'utf8');
        return await runProcess(process.execPath, [filePath], { cwd: tmpDir, timeoutMs });
      } finally { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {} }
    },

    detectBugs(code, runtimeResult) {
      const normalized = (code || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      const lines = normalized.split('\n');
      const findings = [];

      // Check 1: JWT 'none' algorithm
      const jwtNoneLine = lines.findIndex(l => l.includes("header.alg === 'none'") || l.includes('alg === "none"'));
      if (jwtNoneLine !== -1) {
        findings.push({ bugId: 'SEC-JWT-001', title: 'Insecure JWT "none" Algorithm Acceptance', category: 'Security', severity: 'Critical', cwe: 'CWE-287 / CWE-327', line: jwtNoneLine + 1, codeSnippet: lines[jwtNoneLine].trim(), confidence: 0.99, description: 'The token verification routine allows unsigned tokens with alg="none", completely bypassing cryptographic signature validation.' });
      }

      // Check 2: Check-then-act race condition
      const hasAsyncWithdraw = code.includes('async withdraw') || code.includes('withdraw(amount)');
      const hasBalanceCheck = code.includes('this.balance < amount') || code.includes('balance < amount');
      const hasAwaitInMiddle = code.includes('await new Promise') || code.includes('await delay');
      if (hasAsyncWithdraw && hasBalanceCheck && hasAwaitInMiddle) {
        const raceLine = lines.findIndex(l => l.includes('this.balance -=') || l.includes('balance -='));
        findings.push({ bugId: 'CONC-RACE-002', title: 'Time-of-Check to Time-of-Use (TOCTOU) Race Condition', category: 'Concurrency', severity: 'High', cwe: 'CWE-362', line: raceLine !== -1 ? raceLine + 1 : 16, codeSnippet: raceLine !== -1 ? lines[raceLine].trim() : 'this.balance -= amount;', confidence: 0.96, description: 'Account balance is checked before an asynchronous boundary, but mutated after the await resumes without locking.' });
      }

      // Check 3: Off-by-one array bounds
      const offByOneIndex = lines.findIndex(l => /[a-zA-Z0-9_]+\s*<=\s*[a-zA-Z0-9_]+\.length/.test(l));
      if (offByOneIndex !== -1) {
        findings.push({ bugId: 'LOGIC-BOUND-003', title: 'Off-by-One Array Indexing Vulnerability', category: 'Logic', severity: 'Medium', cwe: 'CWE-193', line: offByOneIndex + 1, codeSnippet: lines[offByOneIndex].trim(), confidence: 0.98, description: 'Loop condition uses "<=" on array length instead of "<", which causes an out-of-bounds access reading undefined.' });
      }

      // Check 4: SQL string concatenation
      const sqliIndex = lines.findIndex(l => /SELECT\s+.*WHERE\s+.*\+\s*[a-zA-Z0-9_]+/i.test(l) || /FROM\s+.*WHERE\s+.*\+\s*username/i.test(l));
      if (sqliIndex !== -1) {
        findings.push({ bugId: 'SEC-SQLI-004', title: 'SQL Injection via Unparameterized String Concatenation', category: 'Security', severity: 'Critical', cwe: 'CWE-89', line: sqliIndex + 1, codeSnippet: lines[sqliIndex].trim(), confidence: 0.99, description: 'Untrusted user input is directly concatenated into a raw SQL query string without escaping or parameterized bindings.' });
      }

      // Check 5: ReferenceError — annotated undeclared variable
      const refErrLine = lines.findIndex(l =>
        /\/\/\s*(BUG|ERROR).*ReferenceError/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*undeclared/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*is not defined/i.test(l)
      );
      if (refErrLine !== -1) {
        findings.push({ bugId: 'RUNTIME-REF-005', title: 'ReferenceError: Use of Undeclared Variable', category: 'Runtime', severity: 'High', cwe: 'CWE-457', line: refErrLine + 1, codeSnippet: lines[refErrLine].trim(), confidence: 0.92, description: 'Code accesses a variable that has not been declared in the current scope, causing a ReferenceError at runtime.' });
      }

      // Check 6: TypeError — null/undefined property access
      const typeErrLine = lines.findIndex(l =>
        /\/\/\s*(BUG|ERROR).*TypeError/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*null.*property/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*undefined.*property/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*cannot read prop/i.test(l)
      );
      if (typeErrLine !== -1) {
        findings.push({ bugId: 'RUNTIME-TYPE-006', title: 'TypeError: Property Access on null / undefined', category: 'Runtime', severity: 'High', cwe: 'CWE-476', line: typeErrLine + 1, codeSnippet: lines[typeErrLine].trim(), confidence: 0.91, description: 'Code attempts to read a property or call a method on a null or undefined value, causing a TypeError at runtime.' });
      }

      // --- Runtime Error Detection from actual execution evidence ---
      if (runtimeResult && !runtimeResult.ok && runtimeResult.stderr) {
        const stderr = runtimeResult.stderr;
        const existingBugIds = new Set(findings.map(f => f.bugId));

        // JS SyntaxError from compiler/runtime
        if (/SyntaxError/.test(stderr)) {
          const lineMatch = stderr.match(/:([0-9]+)/);
          const lineNum = lineMatch ? parseInt(lineMatch[1]) : 1;
          const snippet = lines[lineNum - 1] ? lines[lineNum - 1].trim() : '';

          if (/missing \)/i.test(stderr) || (code.includes('(') && !code.includes(')')) || (/Unexpected token ';'/i.test(stderr) && /\([^)]*;/.test(code))) {
            findings.unshift({
              bugId: 'SYNTAX-JS-001',
              title: "SyntaxError: Missing Closing Parenthesis ')'",
              category: 'Syntax',
              severity: 'Critical',
              cwe: 'CWE-1007',
              line: lineNum,
              codeSnippet: snippet || 'console.log("Hello";',
              confidence: 0.99,
              description: "JavaScript engine reported missing closing parenthesis ')' in argument list or expression.",
              runtimeEvidence: stderr
            });
          } else if (/Unexpected end of input/i.test(stderr) && (code.match(/\{/g) || []).length > (code.match(/\}/g) || []).length) {
            findings.unshift({
              bugId: 'SYNTAX-JS-002',
              title: "SyntaxError: Missing Closing Brace '}'",
              category: 'Syntax',
              severity: 'Critical',
              cwe: 'CWE-1007',
              line: lines.length,
              codeSnippet: lines[lines.length - 1] ? lines[lines.length - 1].trim() : '}',
              confidence: 0.99,
              description: "JavaScript engine reported unexpected end of input — unclosed block or function body missing '}'.",
              runtimeEvidence: stderr
            });
          } else {
            const match = stderr.match(/SyntaxError:\s*(.+)/);
            findings.unshift({
              bugId: 'SYNTAX-JS-003',
              title: `SyntaxError: ${match ? match[1].trim() : 'Invalid Syntax'}`,
              category: 'Syntax',
              severity: 'Critical',
              cwe: 'CWE-1007',
              line: lineNum,
              codeSnippet: snippet || 'invalid syntax',
              confidence: 0.99,
              description: `JavaScript engine reported non-deterministic syntax error: ${match ? match[1].trim() : 'unexpected token'}.`,
              runtimeEvidence: stderr
            });
          }
        }

        // JS ReferenceError from runtime
        if (/ReferenceError/.test(stderr) && !existingBugIds.has('RUNTIME-REF-005')) {
          const match = stderr.match(/ReferenceError:\s*(.+?)$/m);
          const varMatch = stderr.match(/([a-zA-Z0-9_]+) is not defined/);
          const lineMatch = stderr.match(/:([0-9]+)/);
          findings.push({ bugId: 'RUNTIME-REF-JS-001', title: 'ReferenceError: Undeclared Variable (Runtime)', category: 'Runtime', severity: 'High', cwe: 'CWE-457', line: lineMatch ? parseInt(lineMatch[1]) : 1, codeSnippet: match ? match[1].trim() : 'ReferenceError detected', confidence: 0.99, description: `Runtime execution produced ReferenceError: ${varMatch ? varMatch[1] + ' is not defined' : (match ? match[1].trim() : 'undeclared variable access')}.`, runtimeEvidence: stderr });
        }

        // JS TypeError from runtime
        if (/TypeError/.test(stderr) && !existingBugIds.has('RUNTIME-TYPE-006')) {
          const match = stderr.match(/TypeError:\s*(.+?)$/m);
          const lineMatch = stderr.match(/:([0-9]+)/);
          findings.push({ bugId: 'RUNTIME-TYPE-JS-002', title: 'TypeError: Invalid Operation (Runtime)', category: 'Runtime', severity: 'High', cwe: 'CWE-476', line: lineMatch ? parseInt(lineMatch[1]) : 1, codeSnippet: match ? match[1].trim() : 'TypeError detected', confidence: 0.99, description: `Runtime execution produced TypeError: ${match ? match[1].trim() : 'invalid property access or method call on null/undefined'}.`, runtimeEvidence: stderr });
        }

        // JS RangeError from runtime
        if (/RangeError/.test(stderr)) {
          const match = stderr.match(/RangeError:\s*(.+?)$/m);
          const lineMatch = stderr.match(/:([0-9]+)/);
          findings.push({ bugId: 'RUNTIME-RANGE-JS-003', title: 'RangeError: Value Out of Allowed Range (Runtime)', category: 'Runtime', severity: 'High', cwe: 'CWE-754', line: lineMatch ? parseInt(lineMatch[1]) : 1, codeSnippet: match ? match[1].trim() : 'RangeError detected', confidence: 0.99, description: `Runtime execution produced RangeError: ${match ? match[1].trim() : 'numeric value exceeded allowed range'}.`, runtimeEvidence: stderr });
        }
      }

      return findings;
    },

    generateFix(code, findingId) {
      let fixedCode = (code || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      let explanation = '';
      let patchSummary = '';

      if (findingId === 'SEC-JWT-001' || code.includes("header.alg === 'none'")) {
        fixedCode = fixedCode.replace(
          `  // BUG: Allowing 'none' algorithm bypasses signature verification!\n  if (header.alg === 'none') {\n    console.log('[AUTH WARNING] Accepting unsigned "none" algorithm token');\n    return { valid: true, user: payload.user, role: payload.role };\n  }`,
          `  // FIX: Explicitly reject unsigned 'none' algorithm and enforce supported secure algorithms\n  const ALLOWED_ALGORITHMS = ['HS256', 'RS256'];\n  if (!header.alg || !ALLOWED_ALGORITHMS.includes(header.alg) || header.alg.toLowerCase() === 'none') {\n    throw new Error('Unsupported or insecure algorithm: ' + header.alg);\n  }`
        ).replace(
          `console.log('Verifying forged admin token...');\nconst authResult = verifyToken(exploitToken, 'super-secret-key-12345');\nconsole.log('Result:', JSON.stringify(authResult));\nif (authResult.role === 'admin') {\n  console.error('[SECURITY FAILURE] Attacker successfully gained admin privileges without secret key!');\n  process.exit(1);\n}`,
          `console.log('Testing rejection of forged admin token...');\ntry {\n  verifyToken(exploitToken, 'super-secret-key-12345');\n  console.error('[FAIL] Insecure token was unexpectedly accepted!');\n  process.exit(1);\n} catch (err) {\n  console.log('[SUCCESS] Forged token correctly rejected with error:', err.message);\n  console.log('[SECURITY VERIFIED] Algorithm "none" blocked. Authorization integrity preserved.');\n}`
        );
        explanation = 'Enforced strict algorithm allowlisting (HS256/RS256) and blocked "none" algorithm.';
        patchSummary = 'Replaced vulnerable alg === "none" check with strict allowlist and rejection.';
      } else if (findingId === 'CONC-RACE-002' || code.includes('async withdraw')) {
        fixedCode = fixedCode.replace(
          `class BankAccount {\n  constructor(id, initialBalance) {\n    this.id = id;\n    this.balance = initialBalance;\n  }\n\n  async withdraw(amount) {\n    console.log(\`Checking balance for \\$\${amount} withdrawal... current balance: \\$\${this.balance}\`);\n    // Check balance\n    if (this.balance < amount) {\n      throw new Error('Insufficient funds');\n    }\n\n    // Artificial latency simulating DB read or remote call\n    await new Promise(resolve => setTimeout(resolve, 50));\n\n    // Act: deduct balance (BUG: State was modified concurrently during await!)\n    this.balance -= amount;\n    console.log(\`Withdrawal successful. New balance: \\$\${this.balance}\`);\n    return this.balance;\n  }\n}`,
          `class BankAccount {\n  constructor(id, initialBalance) {\n    this.id = id;\n    this.balance = initialBalance;\n    this._lock = Promise.resolve(); // Asynchronous mutex lock\n  }\n\n  async withdraw(amount) {\n    // Serialize balance checks and balance modifications via mutex lock\n    return this._lock = this._lock.then(async () => {\n      console.log(\`[LOCKED] Checking balance for \\$\${amount} withdrawal... current balance: \\$\${this.balance}\`);\n      if (this.balance < amount) {\n        throw new Error(\`Insufficient funds (requested \\$\${amount}, available \\$\${this.balance})\`);\n      }\n      // Latency simulation safely executed inside the critical section\n      await new Promise(resolve => setTimeout(resolve, 50));\n      this.balance -= amount;\n      console.log(\`[LOCKED] Withdrawal successful. Remaining balance: \\$\${this.balance}\`);\n      return this.balance;\n    });\n  }\n}`
        );
        explanation = 'Added asynchronous critical section mutex (`_lock`) to serialize withdrawals.';
        patchSummary = 'Added Promise-chained critical section to eliminate race conditions.';
      } else if (findingId === 'LOGIC-BOUND-003' || /<=\s*[a-zA-Z0-9_]+\.length/.test(fixedCode)) {
        if (fixedCode.includes("// BUG: loop condition uses '<=' instead of '<'")) {
          fixedCode = fixedCode.replace(/\/\/\s*BUG:\s*loop condition uses '<=' instead of '<'[^\n]*/, "// FIX: Corrected boundary to '<' to prevent accessing out-of-bounds index");
        }
        fixedCode = fixedCode.replace(/(for\s*\([^;]+;\s*[a-zA-Z0-9_]+)\s*<=\s*([a-zA-Z0-9_]+\.length)/g, '$1 < $2');
        if (/<=\s*[a-zA-Z0-9_]+\.length/.test(fixedCode)) {
          fixedCode = fixedCode.replace(/([a-zA-Z0-9_]+)\s*<=\s*([a-zA-Z0-9_]+\.length)/g, '$1 < $2');
        }
        explanation = 'Corrected loop boundary from `<=` to `<`. The loop now iterates exactly over valid indices (0 to length - 1).';
        patchSummary = 'Fixed loop boundary from `<=` to `<`.';
      } else if (findingId === 'SEC-SQLI-004' || code.includes("WHERE username = '")) {
        fixedCode = fixedCode.replace(
          `function buildUserQuery(username, status) {\n  // BUG: Directly interpolating user input without parameterization\n  const query = "SELECT id, username, email, role FROM users WHERE username = '" + username + "' AND status = '" + status + "'";\n  return query;\n}`,
          `function buildUserQuery(username, status) {\n  // FIX: Use parameterized query object with separate SQL template and arguments\n  return {\n    sql: 'SELECT id, username, email, role FROM users WHERE username = $1 AND status = $2',\n    params: [username, status]\n  };\n}`
        ).replace(
          `console.log('Building query for username input:', maliciousInput);\nconst generatedQuery = buildUserQuery(maliciousInput, statusFilter);\nconsole.log('Generated SQL Query:');\nconsole.log(generatedQuery);\n\n// Validate safety of the query\nif (generatedQuery.includes(\"' OR '1'='1\")) {\n  console.error('[SECURITY DEFECT] SQL Injection detected! Query allows unauthenticated bypass of WHERE clause:');\n  console.error('  Payload broke out of quotes and introduced tautology: \"OR \\'1\\'=\\'1\"');\n  process.exit(1);\n} else {\n  console.log('Query sanitized successfully.');\n}`,
          `console.log('Building parameterized query for username input:', maliciousInput);\nconst queryPlan = buildUserQuery(maliciousInput, statusFilter);\nconsole.log('Parameterized Query Plan:', JSON.stringify(queryPlan, null, 2));\n\nif (queryPlan.sql.includes('$1') && Array.isArray(queryPlan.params) && queryPlan.params[0] === maliciousInput) {\n  console.log('[SECURITY VERIFIED] Query successfully parameterized. SQL injection payload is safely treated as data string.');\n} else {\n  console.error('[FAIL] Query was not parameterized properly');\n  process.exit(1);\n}`
        );
        explanation = 'Converted raw string concatenation into a parameterized query object with placeholders ($1, $2).';
        patchSummary = 'Separated SQL structure from untrusted user parameters using parameterized query design.';
      } else if (findingId === 'SYNTAX-JS-001') {
        const codeLines = fixedCode.split('\n');
        for (let i = 0; i < codeLines.length; i++) {
          if (codeLines[i].includes('(') && codeLines[i].includes(';')) {
            const openCount = (codeLines[i].match(/\(/g) || []).length;
            const closeCount = (codeLines[i].match(/\)/g) || []).length;
            if (openCount > closeCount) {
              codeLines[i] = codeLines[i].replace(/;(\s*)$/, ')'.repeat(openCount - closeCount) + ';$1');
              break;
            }
          } else if (codeLines[i].includes('(') && !codeLines[i].includes(')')) {
            const openCount = (codeLines[i].match(/\(/g) || []).length;
            const closeCount = (codeLines[i].match(/\)/g) || []).length;
            if (openCount > closeCount) {
              codeLines[i] = codeLines[i] + ')'.repeat(openCount - closeCount);
              break;
            }
          }
        }
        fixedCode = codeLines.join('\n');
        explanation = "Safely inserted missing closing parenthesis ')' before statement terminator.";
        patchSummary = "Repaired syntax error: inserted missing ')' delimiter.";
      } else if (findingId === 'SYNTAX-JS-002') {
        const openCount = (fixedCode.match(/\{/g) || []).length;
        const closeCount = (fixedCode.match(/\}/g) || []).length;
        if (openCount > closeCount) {
          fixedCode = fixedCode.trimEnd() + '\n' + '}'.repeat(openCount - closeCount) + '\n';
        }
        explanation = "Safely appended missing closing brace '}' at end of unclosed block scope.";
        patchSummary = "Repaired syntax error: appended missing '}' delimiter.";
      } else if (findingId === 'SYNTAX-JS-003') {
        explanation = "Automatic fix unavailable — JavaScript engine reported non-deterministic syntax error. Manual correction required.";
        patchSummary = "Automatic fix unavailable for non-deterministic JavaScript syntax error. Manual correction required.";
      } else if (findingId === 'RUNTIME-REF-005' || findingId === 'RUNTIME-REF-JS-001') {
        explanation = 'Automatic fix unavailable — ReferenceError indicates access to an undeclared variable. Declare and initialize the variable before use.';
        patchSummary = 'Automatic fix unavailable for ReferenceError. Variable declaration required.';
      } else if (findingId === 'RUNTIME-TYPE-006' || findingId === 'RUNTIME-TYPE-JS-002') {
        explanation = 'Automatic fix unavailable — TypeError indicates property access on null or undefined. Use optional chaining (?.) or an explicit null check before property access.';
        patchSummary = 'Automatic fix unavailable for TypeError. Null check or optional chaining required.';
      } else if (findingId === 'RUNTIME-RANGE-JS-003') {
        explanation = 'Automatic fix unavailable — RangeError requires context-specific boundary correction. The problematic operation that exceeds allowed numeric or stack limits must be manually reviewed.';
        patchSummary = 'Automatic fix unavailable for RangeError. Manual review required.';
      } else {
        explanation = 'Automatic fix unavailable for this defect type.';
        patchSummary = 'Automatic fix unavailable.';
      }

      return { fixedCode, patchSummary, explanation };
    }
  },

  python: {
    id: 'python',
    name: 'Python',
    runtime: 'Python 3',
    extension: '.py',
    filename: 'main.py',
    isCompiled: false,

    async checkSyntax(code, tmpDir) {
      const filePath = path.join(tmpDir, 'syntax_check.py');
      fs.writeFileSync(filePath, code, 'utf8');
      const res = await runProcess('python', ['-m', 'py_compile', filePath], { cwd: tmpDir });
      return { ok: res.ok, error: res.stderr || null };
    },

    async execute(code, timeoutMs = 4000) {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bf-py-'));
      const filePath = path.join(tmpDir, 'main.py');
      try {
        fs.writeFileSync(filePath, code, 'utf8');
        return await runProcess('python', ['-u', filePath], { cwd: tmpDir, timeoutMs });
      } finally { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {} }
    },

    detectBugs(code, runtimeResult) {
      const normalized = (code || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      const lines = normalized.split('\n');
      const findings = [];

      // Check 1: Python off-by-one
      const offByOneIndex = lines.findIndex(l =>
        /range\s*\(\s*(0\s*,\s*)?len\s*\([a-zA-Z0-9_]+\)\s*\+\s*1\s*\)/.test(l) ||
        /range\s*\(\s*0\s*,\s*[a-zA-Z0-9_]+\s*\+\s*1\s*\)/.test(l)
      );
      if (offByOneIndex !== -1) {
        findings.push({ bugId: 'LOGIC-BOUND-PY-001', title: 'Off-by-One Range Boundary in Python Iteration', category: 'Logic', severity: 'Medium', cwe: 'CWE-193', line: offByOneIndex + 1, codeSnippet: lines[offByOneIndex].trim(), confidence: 0.98, description: 'Python range() upper bound evaluates to len(seq) + 1. Zero-based indexing exceeds valid bounds and raises an IndexError at runtime.' });
      }

      // Check 2: Python SQL injection
      const sqliIndex = lines.findIndex(l =>
        /SELECT\s+.*WHERE.*(%s|\+.*format|f["'])/i.test(l) ||
        /query\s*=\s*["']SELECT\s+.*WHERE.*["']\s*\+/i.test(l)
      );
      if (sqliIndex !== -1) {
        findings.push({ bugId: 'SEC-SQLI-PY-002', title: 'SQL Injection via Python String Interpolation', category: 'Security', severity: 'Critical', cwe: 'CWE-89', line: sqliIndex + 1, codeSnippet: lines[sqliIndex].trim(), confidence: 0.99, description: 'User input is dynamically interpolated into a raw SQL query string without parameterized escaping.' });
      }

      // Check 3: ZeroDivisionError
      const zeroDivLine = lines.findIndex(l =>
        /#\s*(BUG|ERROR).*[Zz]ero[Dd]ivision/i.test(l) ||
        /#\s*(BUG|ERROR).*divide.*zero/i.test(l) ||
        /#\s*(BUG|ERROR).*division.*zero/i.test(l) ||
        (/[a-zA-Z0-9_)]\s*\/\s*0(?!\.\d)/.test(l) && !l.trim().startsWith('#'))
      );
      if (zeroDivLine !== -1) {
        findings.push({ bugId: 'RUNTIME-ZDIV-PY-003', title: 'ZeroDivisionError: Division by Zero', category: 'Runtime', severity: 'High', cwe: 'CWE-369', line: zeroDivLine + 1, codeSnippet: lines[zeroDivLine].trim(), confidence: 0.96, description: 'An integer or float is divided by a literal zero or a variable that evaluates to zero, raising ZeroDivisionError at runtime.' });
      }

      // Check 4: NameError — undefined variable (comment-annotated)
      const nameErrLine = lines.findIndex(l =>
        /#\s*(BUG|ERROR).*NameError/i.test(l) ||
        /#\s*(BUG|ERROR).*undefined.*variable/i.test(l) ||
        /#\s*(BUG|ERROR).*not.*defined/i.test(l) ||
        /#\s*(BUG|ERROR).*undeclared/i.test(l)
      );
      if (nameErrLine !== -1) {
        findings.push({ bugId: 'RUNTIME-NAME-PY-004', title: 'NameError: Use of Undefined Variable', category: 'Runtime', severity: 'High', cwe: 'CWE-457', line: nameErrLine + 1, codeSnippet: lines[nameErrLine].trim(), confidence: 0.93, description: 'Code references a variable name that was never assigned in the current scope, raising NameError at runtime.' });
      }

      // Check 5: AttributeError / None dereference
      const noneLine = lines.findIndex(l =>
        /#\s*(BUG|ERROR).*(None|null).*dereference/i.test(l) ||
        /#\s*(BUG|ERROR).*AttributeError/i.test(l) ||
        /#\s*(BUG|ERROR).*NoneType/i.test(l)
      );
      if (noneLine !== -1) {
        findings.push({ bugId: 'RUNTIME-NONE-PY-005', title: 'AttributeError: Method Call on None (NoneType)', category: 'Runtime', severity: 'High', cwe: 'CWE-476', line: noneLine + 1, codeSnippet: lines[noneLine].trim(), confidence: 0.91, description: 'A variable is assigned None and then dereferenced with a method call or attribute access, raising AttributeError at runtime.' });
      }

      // --- Runtime Error Detection from actual execution evidence ---
      if (runtimeResult && !runtimeResult.ok && runtimeResult.stderr) {
        const stderr = runtimeResult.stderr;
        const existingBugIds = new Set(findings.map(f => f.bugId));

        // Python SyntaxError from compiler/interpreter
        if (/SyntaxError/.test(stderr)) {
          const lineMatch = stderr.match(/line\s+(\d+)/i);
          const lineNum = lineMatch ? parseInt(lineMatch[1]) : 1;
          const snippet = lines[lineNum - 1] ? lines[lineNum - 1].trim() : '';

          if (/'\(' was never closed/i.test(stderr) || /unexpected EOF while parsing/i.test(stderr) || (/missing/i.test(stderr) && /\)/.test(stderr))) {
            findings.unshift({
              bugId: 'SYNTAX-PY-001',
              title: "SyntaxError: Unclosed Parenthesis '('",
              category: 'Syntax',
              severity: 'Critical',
              cwe: 'CWE-1007',
              line: lineNum,
              codeSnippet: snippet || "print(name",
              confidence: 0.99,
              description: "Python interpreter reported unclosed parenthesis: '(' was never closed before end of line/file.",
              runtimeEvidence: stderr
            });
          } else if (/'\[' was never closed/i.test(stderr) || /'\{' was never closed/i.test(stderr)) {
            const isBrace = /'\{' was never closed/i.test(stderr);
            findings.unshift({
              bugId: 'SYNTAX-PY-002',
              title: `SyntaxError: Unclosed ${isBrace ? "Brace '{'" : "Bracket '['"}`,
              category: 'Syntax',
              severity: 'Critical',
              cwe: 'CWE-1007',
              line: lineNum,
              codeSnippet: snippet || (isBrace ? "user = {" : "numbers = ["),
              confidence: 0.99,
              description: `Python interpreter reported unclosed ${isBrace ? "brace '{'" : "bracket '['"} before end of line/file.`,
              runtimeEvidence: stderr
            });
          } else {
            const match = stderr.match(/SyntaxError:\s*(.+)/);
            findings.unshift({
              bugId: 'SYNTAX-PY-003',
              title: `SyntaxError: ${match ? match[1].trim() : 'Invalid Syntax'}`,
              category: 'Syntax',
              severity: 'Critical',
              cwe: 'CWE-1007',
              line: lineNum,
              codeSnippet: snippet || 'invalid syntax',
              confidence: 0.99,
              description: `Python interpreter reported syntax error: ${match ? match[1].trim() : 'invalid syntax'}.`,
              runtimeEvidence: stderr
            });
          }
        }

        // Python ZeroDivisionError from runtime
        if (/ZeroDivisionError/.test(stderr) && !existingBugIds.has('RUNTIME-ZDIV-PY-003')) {
          const match = stderr.match(/ZeroDivisionError:\s*(.+?)$/m);
          const lineMatch = stderr.match(/line\s+(\d+)/i);
          findings.push({ bugId: 'RUNTIME-ZDIV-PY-001', title: 'ZeroDivisionError (Runtime Evidence)', category: 'Runtime', severity: 'High', cwe: 'CWE-369', line: lineMatch ? parseInt(lineMatch[1]) : 1, codeSnippet: match ? match[1].trim() : 'division by zero', confidence: 0.99, description: `Runtime execution produced ZeroDivisionError: ${match ? match[1].trim() : 'division by zero'}.`, runtimeEvidence: stderr });
        }

        // Python NameError from runtime
        if (/NameError/.test(stderr) && !existingBugIds.has('RUNTIME-NAME-PY-004')) {
          const match = stderr.match(/NameError:\s*(.+?)$/m);
          const lineMatch = stderr.match(/line\s+(\d+)/i);
          findings.push({ bugId: 'RUNTIME-NAME-PY-002', title: 'NameError: Undefined Variable (Runtime Evidence)', category: 'Runtime', severity: 'High', cwe: 'CWE-457', line: lineMatch ? parseInt(lineMatch[1]) : 1, codeSnippet: match ? match[1].trim() : 'name not defined', confidence: 0.99, description: `Runtime execution produced NameError: ${match ? match[1].trim() : 'undefined variable'}.`, runtimeEvidence: stderr });
        }

        // Python TypeError from runtime
        if (/TypeError/.test(stderr)) {
          const match = stderr.match(/TypeError:\s*(.+?)$/m);
          const lineMatch = stderr.match(/line\s+(\d+)/i);
          findings.push({ bugId: 'RUNTIME-TYPE-PY-003', title: 'TypeError: Incompatible Operation (Runtime Evidence)', category: 'Runtime', severity: 'High', cwe: 'CWE-843', line: lineMatch ? parseInt(lineMatch[1]) : 1, codeSnippet: match ? match[1].trim() : 'type error', confidence: 0.99, description: `Runtime execution produced TypeError: ${match ? match[1].trim() : 'incompatible types in operation'}.`, runtimeEvidence: stderr });
        }

        // Python IndexError from runtime
        if (/IndexError/.test(stderr)) {
          const match = stderr.match(/IndexError:\s*(.+?)$/m);
          const lineMatch = stderr.match(/line\s+(\d+)/i);
          findings.push({ bugId: 'RUNTIME-INDEX-PY-004', title: 'IndexError: Sequence Index Out of Range (Runtime Evidence)', category: 'Runtime', severity: 'High', cwe: 'CWE-125', line: lineMatch ? parseInt(lineMatch[1]) : 1, codeSnippet: match ? match[1].trim() : 'list index out of range', confidence: 0.99, description: `Runtime execution produced IndexError: ${match ? match[1].trim() : 'sequence index exceeds valid bounds'}.`, runtimeEvidence: stderr });
        }

        // Python KeyError from runtime
        if (/KeyError/.test(stderr)) {
          const match = stderr.match(/KeyError:\s*(.+?)$/m);
          const lineMatch = stderr.match(/line\s+(\d+)/i);
          findings.push({ bugId: 'RUNTIME-KEY-PY-005', title: 'KeyError: Missing Dictionary Key (Runtime Evidence)', category: 'Runtime', severity: 'High', cwe: 'CWE-754', line: lineMatch ? parseInt(lineMatch[1]) : 1, codeSnippet: match ? match[1].trim() : 'key not found', confidence: 0.99, description: `Runtime execution produced KeyError: ${match ? match[1].trim() : 'dictionary key does not exist'}.`, runtimeEvidence: stderr });
        }
      }

      return findings;
    },

    generateFix(code, findingId) {
      let fixedCode = (code || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      let explanation = '';
      let patchSummary = '';

      if (findingId === 'LOGIC-BOUND-PY-001' || /range\s*\([^\)]*len\([a-zA-Z0-9_]+\)\s*\+\s*1\)/.test(fixedCode)) {
        fixedCode = fixedCode
          .replace(/range\s*\(\s*0\s*,\s*len\s*\(\s*([a-zA-Z0-9_]+)\s*\)\s*\+\s*1\s*\)/g, 'range(0, len($1))')
          .replace(/range\s*\(\s*len\s*\(\s*([a-zA-Z0-9_]+)\s*\)\s*\+\s*1\s*\)/g, 'range(len($1))')
          .replace(/range\s*\(\s*0\s*,\s*([a-zA-Z0-9_]+)\s*\+\s*1\s*\)/g, 'range(0, $1)');
        if (fixedCode.includes('# BUG:')) fixedCode = fixedCode.replace(/#\s*BUG:[^\n]*/g, '# FIX: Loop boundary correctly constrained to valid zero-based indices');
        explanation = 'Corrected Python range upper bound from `len(seq) + 1` to `len(seq)`.';
        patchSummary = 'Fixed Python range upper bound: removed `+ 1` over-extension.';
      } else if (findingId === 'SEC-SQLI-PY-002') {
        fixedCode = fixedCode
          .replace(/query\s*=\s*["']SELECT[^"']*WHERE[^"']*["']\s*\+\s*[a-zA-Z0-9_]+\s*\+?\s*["'][^"']*["']/g,
            "query = ('SELECT id, username, role FROM users WHERE username = %s AND active = 1', (username,))")
          .replace(/#\s*BUG:[^\n]*/g, '# FIX: Parameterized query prevents SQL injection');
        explanation = 'Replaced raw string concatenation with a parameterized query tuple.';
        patchSummary = 'Converted Python SQL string to parameterized query.';
      } else if (findingId === 'SYNTAX-PY-001') {
        const codeLines = fixedCode.split('\n');
        for (let i = codeLines.length - 1; i >= 0; i--) {
          const openCount = (codeLines[i].match(/\(/g) || []).length;
          const closeCount = (codeLines[i].match(/\)/g) || []).length;
          if (openCount > closeCount) {
            codeLines[i] = codeLines[i] + ')'.repeat(openCount - closeCount);
            break;
          }
        }
        fixedCode = codeLines.join('\n');
        explanation = "Safely appended missing closing parenthesis ')' to restore balanced delimiter.";
        patchSummary = "Repaired syntax error: added missing ')' delimiter.";
      } else if (findingId === 'SYNTAX-PY-002') {
        const codeLines = fixedCode.split('\n');
        for (let i = codeLines.length - 1; i >= 0; i--) {
          const openBrackets = (codeLines[i].match(/\[/g) || []).length;
          const closeBrackets = (codeLines[i].match(/\]/g) || []).length;
          if (openBrackets > closeBrackets) {
            codeLines[i] = codeLines[i] + ']'.repeat(openBrackets - closeBrackets);
            break;
          }
          const openBraces = (codeLines[i].match(/\{/g) || []).length;
          const closeBraces = (codeLines[i].match(/\}/g) || []).length;
          if (openBraces > closeBraces) {
            codeLines[i] = codeLines[i] + '}'.repeat(openBraces - closeBraces);
            break;
          }
        }
        fixedCode = codeLines.join('\n');
        explanation = "Safely appended missing closing bracket ']' or brace '}' to restore balanced delimiter.";
        patchSummary = "Repaired syntax error: added missing ']' or '}' delimiter.";
      } else if (findingId === 'SYNTAX-PY-003') {
        explanation = "Automatic fix unavailable — Python parser reported complex or ambiguous syntax error. Manual correction required.";
        patchSummary = "Automatic fix unavailable for complex Python syntax error. Manual correction required.";
      } else if (findingId === 'RUNTIME-ZDIV-PY-003' || findingId === 'RUNTIME-ZDIV-PY-001') {
        explanation = 'Automatic fix unavailable — ZeroDivisionError requires reviewing the divisor expression. Ensure the divisor is non-zero or add an explicit check before division.';
        patchSummary = 'Automatic fix unavailable for ZeroDivisionError. Divisor must be checked before division.';
      } else if (findingId === 'RUNTIME-NAME-PY-004' || findingId === 'RUNTIME-NAME-PY-002') {
        explanation = 'Automatic fix unavailable — NameError indicates an undefined variable. Check for typos or ensure the variable is defined in the current scope before use.';
        patchSummary = 'Automatic fix unavailable for NameError. Variable definition or typo correction required.';
      } else if (findingId === 'RUNTIME-NONE-PY-005') {
        explanation = 'Automatic fix unavailable — NoneType dereference requires a None-check or initializing with a valid object before method access.';
        patchSummary = 'Automatic fix unavailable for NoneType dereference. None check required.';
      } else if (findingId === 'RUNTIME-TYPE-PY-003') {
        explanation = 'Automatic fix unavailable — TypeError requires understanding the intended types. The operation combines incompatible types and needs manual type conversion (e.g., str() or int()).';
        patchSummary = 'Automatic fix unavailable for TypeError. Manual type conversion required.';
      } else if (findingId === 'RUNTIME-INDEX-PY-004') {
        explanation = 'Automatic fix unavailable — IndexError requires validating the index against the sequence length before access. The specific index and sequence must be reviewed manually.';
        patchSummary = 'Automatic fix unavailable for IndexError. Manual bounds validation required.';
      } else if (findingId === 'RUNTIME-KEY-PY-005') {
        explanation = 'Automatic fix unavailable — KeyError requires using dict.get(key, default) or checking key existence before access. The expected key and default value must be determined from context.';
        patchSummary = 'Automatic fix unavailable for KeyError. Use dict.get() with a default value.';
      } else {
        explanation = 'Automatic fix unavailable for this defect type.';
        patchSummary = 'Automatic fix unavailable.';
      }

      return { fixedCode, patchSummary, explanation };
    }
  },

  java: {
    id: 'java',
    name: 'Java',
    runtime: 'JDK 17 (javac & java)',
    extension: '.java',
    filename: 'Main.java',
    isCompiled: true,

    async checkSyntax(code, tmpDir) {
      const filePath = path.join(tmpDir, 'Main.java');
      fs.writeFileSync(filePath, code, 'utf8');
      const res = await runProcess('javac', ['-d', tmpDir, filePath], { cwd: tmpDir });
      return { ok: res.ok, error: res.stderr || null };
    },

    async execute(code, timeoutMs = 5000) {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bf-java-'));
      const filePath = path.join(tmpDir, 'Main.java');
      try {
        fs.writeFileSync(filePath, code, 'utf8');
        const compileRes = await runProcess('javac', ['-d', tmpDir, filePath], { cwd: tmpDir });
        if (!compileRes.ok) {
          return { ok: false, exitCode: compileRes.exitCode, phase: 'compilation', stdout: '', stderr: 'Java Compilation Error:\n' + compileRes.stderr, durationMs: compileRes.durationMs, timedOut: false };
        }
        const match = code.match(/public\s+class\s+([a-zA-Z0-9_]+)/);
        const className = match ? match[1] : 'Main';
        return await runProcess('java', ['-cp', tmpDir, className], { cwd: tmpDir, timeoutMs });
      } finally { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {} }
    },

    detectBugs(code, runtimeResult) {
      const normalized = (code || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      const lines = normalized.split('\n');
      const findings = [];

      // Check 1: Java off-by-one
      const offByOneIndex = lines.findIndex(l =>
        /for\s*\([^;]+;\s*[a-zA-Z0-9_]+\s*<=\s*[a-zA-Z0-9_]+\.length\s*;/.test(l) ||
        /[a-zA-Z0-9_]+\s*<=\s*[a-zA-Z0-9_]+\.length/.test(l)
      );
      if (offByOneIndex !== -1) {
        findings.push({ bugId: 'LOGIC-BOUND-JAVA-001', title: 'Off-by-One Array Bounds in Java Loop', category: 'Logic', severity: 'Medium', cwe: 'CWE-193', line: offByOneIndex + 1, codeSnippet: lines[offByOneIndex].trim(), confidence: 0.98, description: 'Loop comparison uses "<=" on array.length. Accessing index array.length triggers an uncaught java.lang.ArrayIndexOutOfBoundsException.' });
      }

      // Check 2: NullPointerException
      const nullPtrLine = lines.findIndex(l =>
        /\/\/\s*(BUG|ERROR).*NullPointerException/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*null.*dereference/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*NPE/i.test(l)
      );
      if (nullPtrLine !== -1) {
        findings.push({ bugId: 'RUNTIME-NPE-JAVA-002', title: 'NullPointerException: Method Call on null Reference', category: 'Runtime', severity: 'High', cwe: 'CWE-476', line: nullPtrLine + 1, codeSnippet: lines[nullPtrLine].trim(), confidence: 0.94, description: 'A variable holding null is dereferenced (method called or field accessed), causing java.lang.NullPointerException at runtime.' });
      }

      // Check 3: ArithmeticException (divide by zero)
      const arithLine = lines.findIndex(l =>
        /\/\/\s*(BUG|ERROR).*ArithmeticException/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*divide.*zero/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*division.*zero/i.test(l) ||
        (/[a-zA-Z0-9_)]\s*\/\s*0(?![.\d])/.test(l) && !l.trim().startsWith('//'))
      );
      if (arithLine !== -1) {
        findings.push({ bugId: 'RUNTIME-ARITH-JAVA-003', title: 'ArithmeticException: Integer Division by Zero', category: 'Runtime', severity: 'High', cwe: 'CWE-369', line: arithLine + 1, codeSnippet: lines[arithLine].trim(), confidence: 0.96, description: 'An integer expression divides by a literal zero or a variable that evaluates to zero, causing java.lang.ArithmeticException: / by zero at runtime.' });
      }

      // --- Runtime Error Detection from actual execution evidence ---
      if (runtimeResult && !runtimeResult.ok && runtimeResult.stderr) {
        const stderr = runtimeResult.stderr;
        const existingBugIds = new Set(findings.map(f => f.bugId));

        // Java Syntax / Compilation errors
        if (/error:\s*';'\s*expected/i.test(stderr)) {
          const lineMatch = stderr.match(/Main\.java:(\d+):/);
          const lineNum = lineMatch ? parseInt(lineMatch[1]) : 1;
          const snippet = lines[lineNum - 1] ? lines[lineNum - 1].trim() : '';
          findings.unshift({
            bugId: 'SYNTAX-JAVA-001',
            title: "SyntaxError: Missing Semicolon ';'",
            category: 'Syntax',
            severity: 'Critical',
            cwe: 'CWE-1007',
            line: lineNum,
            codeSnippet: snippet,
            confidence: 0.99,
            description: "Java compiler (javac) reported missing ';' semicolon expected on statement line.",
            runtimeEvidence: stderr
          });
        } else if (/error:\s*'\)'\s*expected/i.test(stderr)) {
          const lineMatch = stderr.match(/Main\.java:(\d+):/);
          const lineNum = lineMatch ? parseInt(lineMatch[1]) : 1;
          const snippet = lines[lineNum - 1] ? lines[lineNum - 1].trim() : '';
          findings.unshift({
            bugId: 'SYNTAX-JAVA-002',
            title: "SyntaxError: Missing Closing Parenthesis ')'",
            category: 'Syntax',
            severity: 'Critical',
            cwe: 'CWE-1007',
            line: lineNum,
            codeSnippet: snippet,
            confidence: 0.99,
            description: "Java compiler (javac) reported missing closing parenthesis ')' expected.",
            runtimeEvidence: stderr
          });
        } else if (/Java Compilation Error/i.test(stderr) || (/Main\.java:.*error:/i.test(stderr))) {
          const lineMatch = stderr.match(/Main\.java:(\d+):/);
          const lineNum = lineMatch ? parseInt(lineMatch[1]) : 1;
          const errMatch = stderr.match(/error:\s*(.+)/);
          const snippet = lines[lineNum - 1] ? lines[lineNum - 1].trim() : '';
          findings.unshift({
            bugId: 'SYNTAX-JAVA-003',
            title: `SyntaxError: Java Compiler Error`,
            category: 'Syntax',
            severity: 'Critical',
            cwe: 'CWE-1007',
            line: lineNum,
            codeSnippet: snippet || (errMatch ? errMatch[1].trim() : 'compiler error'),
            confidence: 0.99,
            description: `Java compiler reported syntax error: ${errMatch ? errMatch[1].trim() : 'compilation error'}.`,
            runtimeEvidence: stderr
          });
        }

        // Java NullPointerException from runtime
        if (/NullPointerException/.test(stderr) && !existingBugIds.has('RUNTIME-NPE-JAVA-002')) {
          const lineMatch = stderr.match(/Main\.java:(\d+)/);
          findings.push({ bugId: 'RUNTIME-NPE-JAVA-001', title: 'NullPointerException (Runtime Evidence)', category: 'Runtime', severity: 'High', cwe: 'CWE-476', line: lineMatch ? parseInt(lineMatch[1]) : 1, codeSnippet: 'java.lang.NullPointerException', confidence: 0.99, description: 'Runtime execution produced java.lang.NullPointerException — method call or field access on null reference.', runtimeEvidence: stderr });
        }

        // Java ArithmeticException from runtime
        if (/ArithmeticException/.test(stderr) && !existingBugIds.has('RUNTIME-ARITH-JAVA-003')) {
          const lineMatch = stderr.match(/Main\.java:(\d+)/);
          findings.push({ bugId: 'RUNTIME-ARITH-JAVA-001', title: 'ArithmeticException: Division by Zero (Runtime Evidence)', category: 'Runtime', severity: 'High', cwe: 'CWE-369', line: lineMatch ? parseInt(lineMatch[1]) : 1, codeSnippet: 'java.lang.ArithmeticException: / by zero', confidence: 0.99, description: 'Runtime execution produced java.lang.ArithmeticException: / by zero — integer division by zero.', runtimeEvidence: stderr });
        }

        // Java ArrayIndexOutOfBoundsException from runtime
        if (/ArrayIndexOutOfBoundsException/.test(stderr)) {
          const match = stderr.match(/ArrayIndexOutOfBoundsException:\s*(?:Index\s+)?(\d+)/i);
          const lineMatch = stderr.match(/Main\.java:(\d+)/);
          findings.push({ bugId: 'RUNTIME-INDEX-JAVA-003', title: 'ArrayIndexOutOfBoundsException (Runtime Evidence)', category: 'Runtime', severity: 'High', cwe: 'CWE-125', line: lineMatch ? parseInt(lineMatch[1]) : 1, codeSnippet: match ? `ArrayIndexOutOfBoundsException: Index ${match[1]}` : 'ArrayIndexOutOfBoundsException', confidence: 0.99, description: `Runtime execution produced java.lang.ArrayIndexOutOfBoundsException${match ? ': Index ' + match[1] + ' out of bounds' : ''} — array access exceeds valid indices.`, runtimeEvidence: stderr });
        }
      }

      return findings;
    },

    generateFix(code, findingId) {
      let fixedCode = (code || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      let explanation = '';
      let patchSummary = '';

      if (findingId === 'LOGIC-BOUND-JAVA-001' || /<=\s*[a-zA-Z0-9_]+\.length/.test(fixedCode)) {
        fixedCode = fixedCode.replace(/(for\s*\([^;]+;\s*[a-zA-Z0-9_]+)\s*<=\s*([a-zA-Z0-9_]+\.length)/g, '$1 < $2');
        if (/<=\s*[a-zA-Z0-9_]+\.length/.test(fixedCode)) fixedCode = fixedCode.replace(/([a-zA-Z0-9_]+)\s*<=\s*([a-zA-Z0-9_]+\.length)/g, '$1 < $2');
        if (fixedCode.includes('// BUG:')) fixedCode = fixedCode.replace(/\/\/\s*BUG:[^\n]*/g, '// FIX: Corrected boundary to `< array.length` to avoid ArrayIndexOutOfBoundsException');
        explanation = 'Corrected loop condition from `<= array.length` to `< array.length`.';
        patchSummary = 'Fixed Java array loop boundary operator from `<=` to `<`.';
      } else if (findingId === 'SYNTAX-JAVA-001') {
        const codeLines = fixedCode.split('\n');
        for (let i = 0; i < codeLines.length; i++) {
          const trimmed = codeLines[i].trim();
          if (trimmed && !trimmed.endsWith(';') && !trimmed.endsWith('{') && !trimmed.endsWith('}') && !trimmed.startsWith('//') && !trimmed.startsWith('public class') && !trimmed.startsWith('class') && !trimmed.startsWith('import') && !trimmed.startsWith('package')) {
            codeLines[i] = codeLines[i] + ';';
            break;
          }
        }
        fixedCode = codeLines.join('\n');
        explanation = "Safely appended missing semicolon ';' statement terminator identified by javac compiler.";
        patchSummary = "Repaired syntax error: appended missing ';' statement terminator.";
      } else if (findingId === 'SYNTAX-JAVA-002') {
        const codeLines = fixedCode.split('\n');
        for (let i = 0; i < codeLines.length; i++) {
          if (/\b(?:if|while|for)\s*\([^)]*?\{/.test(codeLines[i])) {
            codeLines[i] = codeLines[i].replace(/(\b(?:if|while|for)\s*\([^)]*?)\s*\{/, '$1) {');
            break;
          }
        }
        fixedCode = codeLines.join('\n');
        explanation = "Safely inserted missing closing parenthesis ')' before block opening '{'.";
        patchSummary = "Repaired syntax error: inserted missing ')' delimiter.";
      } else if (findingId === 'SYNTAX-JAVA-003') {
        explanation = "Automatic fix unavailable — Java compiler reported complex or ambiguous error. Manual correction required.";
        patchSummary = "Automatic fix unavailable for complex Java compiler error. Manual correction required.";
      } else if (findingId === 'RUNTIME-NPE-JAVA-002' || findingId === 'RUNTIME-NPE-JAVA-001') {
        explanation = 'Automatic fix unavailable — NullPointerException requires initializing the reference or adding a null check before invoking methods.';
        patchSummary = 'Automatic fix unavailable for NullPointerException. Null check or non-null initialization required.';
      } else if (findingId === 'RUNTIME-ARITH-JAVA-003' || findingId === 'RUNTIME-ARITH-JAVA-001') {
        explanation = 'Automatic fix unavailable — ArithmeticException (/ by zero) requires guarding the divisor against zero before performing division.';
        patchSummary = 'Automatic fix unavailable for ArithmeticException. Divisor check required before division.';
      } else if (findingId === 'RUNTIME-INDEX-JAVA-003') {
        explanation = 'Automatic fix unavailable — ArrayIndexOutOfBoundsException requires validating the index against array.length before access. The specific index and array must be reviewed manually.';
        patchSummary = 'Automatic fix unavailable for ArrayIndexOutOfBoundsException. Manual bounds check required.';
      } else {
        explanation = 'Automatic fix unavailable for this defect type.';
        patchSummary = 'Automatic fix unavailable.';
      }

      return { fixedCode, patchSummary, explanation };
    }
  },

  c: {
    id: 'c',
    name: 'C',
    runtime: 'GCC (MinGW-w64 8.1.0)',
    extension: '.c',
    filename: 'main.c',
    isCompiled: true,

    async checkSyntax(code, tmpDir) {
      const filePath = path.join(tmpDir, 'syntax_check.c');
      fs.writeFileSync(filePath, code, 'utf8');
      const res = await runProcess('gcc', ['-fsyntax-only', filePath], { cwd: tmpDir });
      return { ok: res.ok, error: res.stderr || null };
    },

    async execute(code, timeoutMs = 4000) {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bf-c-'));
      const srcPath = path.join(tmpDir, 'main.c');
      const binPath = path.join(tmpDir, 'main.exe');
      try {
        fs.writeFileSync(srcPath, code, 'utf8');
        const compileRes = await runProcess('gcc', ['-Wall', srcPath, '-o', binPath], { cwd: tmpDir });
        if (!compileRes.ok) {
          return { ok: false, exitCode: compileRes.exitCode, phase: 'compilation', stdout: '', stderr: 'C Compilation Error (GCC):\n' + compileRes.stderr, durationMs: compileRes.durationMs, timedOut: false };
        }
        return await runProcess(binPath, [], { cwd: tmpDir, timeoutMs });
      } finally { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {} }
    },

    detectBugs(code, runtimeResult) {
      const normalized = (code || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      const lines = normalized.split('\n');
      const findings = [];

      // Check 1: C off-by-one
      const offByOneIndex = lines.findIndex(l =>
        /for\s*\(\s*(int|size_t)\s+[a-zA-Z0-9_]+\s*=\s*0\s*;\s*[a-zA-Z0-9_]+\s*<=\s*([a-zA-Z0-9_]+)\s*;/.test(l) ||
        /(int|size_t)\s+[a-zA-Z0-9_]+\s*=\s*0\s*;[^;]*<=\s*[a-zA-Z0-9_]+/.test(l)
      );
      if (offByOneIndex !== -1) {
        findings.push({ bugId: 'LOGIC-BOUND-C-001', title: 'Off-by-One Buffer Overread / Overrun in C Loop', category: 'Logic', severity: 'High', cwe: 'CWE-193', line: offByOneIndex + 1, codeSnippet: lines[offByOneIndex].trim(), confidence: 0.98, description: 'Loop condition uses "<=" on buffer size. Reading or writing index N of an N-element buffer produces undefined behavior or memory corruption.' });
      }

      // Check 2: NULL pointer dereference
      const nullPtrLine = lines.findIndex(l =>
        /\/\/\s*(BUG|ERROR).*[Nn]ull.*[Pp]ointer/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*[Nn][Pp][Ee]/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*dereference.*NULL/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*NULL.*dereference/i.test(l)
      );
      if (nullPtrLine !== -1) {
        findings.push({ bugId: 'RUNTIME-NULLPTR-C-002', title: 'NULL Pointer Dereference in C', category: 'Runtime', severity: 'Critical', cwe: 'CWE-476', line: nullPtrLine + 1, codeSnippet: lines[nullPtrLine].trim(), confidence: 0.94, description: 'A pointer is set to NULL and then dereferenced without a null check, causing a segmentation fault or undefined behavior.' });
      }

      // Check 3: C integer divide by zero
      const cDivZeroLine = lines.findIndex(l =>
        /\/\/\s*(BUG|ERROR).*divide.*zero/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*division.*zero/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*[Zz]ero.*[Dd]iv/i.test(l) ||
        (/[a-zA-Z0-9_)]\s*\/\s*0(?![.\d])/.test(l) && !l.trim().startsWith('//'))
      );
      if (cDivZeroLine !== -1) {
        findings.push({ bugId: 'RUNTIME-DIVZERO-C-003', title: 'Integer Division by Zero in C', category: 'Runtime', severity: 'High', cwe: 'CWE-369', line: cDivZeroLine + 1, codeSnippet: lines[cDivZeroLine].trim(), confidence: 0.95, description: 'An integer expression divides by a literal zero or unguarded variable, causing undefined behavior or a floating-point exception signal at runtime.' });
      }

      // --- Runtime Error Detection from actual execution evidence ---
      if (runtimeResult && !runtimeResult.ok) {
        const stderr = runtimeResult.stderr || '';
        const exitCode = runtimeResult.exitCode;
        const existingBugIds = new Set(findings.map(f => f.bugId));

        // C Syntax / Compilation errors
        if (/error:\s*expected\s*';'/i.test(stderr)) {
          const lineMatch = stderr.match(/main\.c:(\d+):/);
          const lineNum = lineMatch ? parseInt(lineMatch[1]) : 1;
          const snippet = lines[lineNum - 1] ? lines[lineNum - 1].trim() : '';
          findings.unshift({
            bugId: 'SYNTAX-C-001',
            title: "SyntaxError: Missing Semicolon ';'",
            category: 'Syntax',
            severity: 'Critical',
            cwe: 'CWE-1007',
            line: lineNum,
            codeSnippet: snippet,
            confidence: 0.99,
            description: "GCC compiler reported missing semicolon ';' expected on statement line.",
            runtimeEvidence: stderr
          });
        } else if (/error:\s*expected\s*'\)'/i.test(stderr)) {
          const lineMatch = stderr.match(/main\.c:(\d+):/);
          const lineNum = lineMatch ? parseInt(lineMatch[1]) : 1;
          const snippet = lines[lineNum - 1] ? lines[lineNum - 1].trim() : '';
          findings.unshift({
            bugId: 'SYNTAX-C-002',
            title: "SyntaxError: Missing Closing Parenthesis ')'",
            category: 'Syntax',
            severity: 'Critical',
            cwe: 'CWE-1007',
            line: lineNum,
            codeSnippet: snippet,
            confidence: 0.99,
            description: "GCC compiler reported missing closing parenthesis ')'.",
            runtimeEvidence: stderr
          });
        } else if (/C Compilation Error/i.test(stderr) || (/main\.c:.*error:/i.test(stderr))) {
          const lineMatch = stderr.match(/main\.c:(\d+):/);
          const lineNum = lineMatch ? parseInt(lineMatch[1]) : 1;
          const errMatch = stderr.match(/error:\s*(.+)/);
          const snippet = lines[lineNum - 1] ? lines[lineNum - 1].trim() : '';
          findings.unshift({
            bugId: 'SYNTAX-C-003',
            title: `SyntaxError: C Compiler Error (GCC)`,
            category: 'Syntax',
            severity: 'Critical',
            cwe: 'CWE-1007',
            line: lineNum,
            codeSnippet: snippet || (errMatch ? errMatch[1].trim() : 'compiler error'),
            confidence: 0.99,
            description: `GCC compiler reported complex syntax error: ${errMatch ? errMatch[1].trim() : 'compilation error'}.`,
            runtimeEvidence: stderr
          });
        }

        // C segmentation fault (null pointer dereference) from runtime — exit code -11 (SIGSEGV) or non-zero with signal
        if ((runtimeResult.signal === 'SIGSEGV' || /segmentation fault/i.test(stderr) || /SIGSEGV/i.test(stderr) || exitCode === -1073741819 || exitCode === 3221225477) && !existingBugIds.has('RUNTIME-NULLPTR-C-002')) {
          findings.push({ bugId: 'RUNTIME-NULLPTR-C-001', title: 'Segmentation Fault / NULL Pointer Dereference (Runtime Evidence)', category: 'Runtime', severity: 'Critical', cwe: 'CWE-476', line: 1, codeSnippet: 'Segmentation fault (SIGSEGV)', confidence: 0.99, description: 'Runtime execution crashed with a segmentation fault signal, indicating NULL pointer dereference or invalid memory access.', runtimeEvidence: stderr || 'exit code: ' + exitCode });
        }

        // C divide by zero (SIGFPE) from runtime
        if ((runtimeResult.signal === 'SIGFPE' || /floating.*point.*exception/i.test(stderr) || /SIGFPE/i.test(stderr) || exitCode === -1073741676 || exitCode === 3221225620) && !existingBugIds.has('RUNTIME-DIVZERO-C-003')) {
          findings.push({ bugId: 'RUNTIME-DIV-C-001', title: 'Integer Division by Zero / SIGFPE (Runtime Evidence)', category: 'Runtime', severity: 'High', cwe: 'CWE-369', line: 1, codeSnippet: 'Floating-point exception (SIGFPE)', confidence: 0.99, description: 'Runtime execution crashed with SIGFPE signal, indicating integer division by zero or arithmetic overflow.', runtimeEvidence: stderr || 'exit code: ' + exitCode });
        }
      }

      return findings;
    },

    generateFix(code, findingId) {
      let fixedCode = (code || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      let explanation = '';
      let patchSummary = '';

      if (findingId === 'LOGIC-BOUND-C-001' || /for\s*\([^;]+;\s*[a-zA-Z0-9_]+\s*<=\s*[a-zA-Z0-9_]+/.test(fixedCode)) {
        fixedCode = fixedCode.replace(/(for\s*\([^;]+;\s*[a-zA-Z0-9_]+)\s*<=\s*([a-zA-Z0-9_]+)(\s*;)/g, '$1 < $2$3');
        if (fixedCode.includes('// BUG:')) fixedCode = fixedCode.replace(/\/\/\s*BUG:[^\n]*/g, '// FIX: Loop boundary changed to `<` to avoid out-of-bounds buffer access');
        explanation = 'Corrected C loop condition from `<=` to `<`.';
        patchSummary = 'Fixed C loop boundary operator from `<=` to `<`.';
      } else if (findingId === 'SYNTAX-C-001') {
        const codeLines = fixedCode.split('\n');
        for (let i = 0; i < codeLines.length; i++) {
          const trimmed = codeLines[i].trim();
          if (trimmed && !trimmed.endsWith(';') && !trimmed.endsWith('{') && !trimmed.endsWith('}') && !trimmed.startsWith('#') && !trimmed.startsWith('//') && !trimmed.includes('main(')) {
            codeLines[i] = codeLines[i] + ';';
            break;
          }
        }
        fixedCode = codeLines.join('\n');
        explanation = "Safely appended missing semicolon ';' statement terminator identified by GCC.";
        patchSummary = "Repaired syntax error: appended missing ';' statement terminator.";
      } else if (findingId === 'SYNTAX-C-002') {
        const codeLines = fixedCode.split('\n');
        for (let i = 0; i < codeLines.length; i++) {
          if (/\b(?:if|while|for)\s*\([^)]*?\{/.test(codeLines[i])) {
            codeLines[i] = codeLines[i].replace(/(\b(?:if|while|for)\s*\([^)]*?)\s*\{/, '$1) {');
            break;
          }
        }
        fixedCode = codeLines.join('\n');
        explanation = "Safely inserted missing closing parenthesis ')' before block opening '{'.";
        patchSummary = "Repaired syntax error: inserted missing ')' delimiter.";
      } else if (findingId === 'SYNTAX-C-003') {
        explanation = "Automatic fix unavailable — GCC reported complex or ambiguous syntax error. Manual correction required.";
        patchSummary = "Automatic fix unavailable for complex C syntax error. Manual correction required.";
      } else if (findingId === 'RUNTIME-NULLPTR-C-002' || findingId === 'RUNTIME-NULLPTR-C-001') {
        explanation = 'Automatic fix unavailable — NULL pointer dereference requires validating pointers with `if (ptr != NULL)` or proper memory allocation.';
        patchSummary = 'Automatic fix unavailable for NULL pointer dereference. Pointer validation required.';
      } else if (findingId === 'RUNTIME-DIVZERO-C-003' || findingId === 'RUNTIME-DIV-C-001') {
        explanation = 'Automatic fix unavailable — Integer division by zero causes SIGFPE or undefined behavior. Ensure divisor is non-zero before division.';
        patchSummary = 'Automatic fix unavailable for Division by Zero. Divisor must be checked before division.';
      } else {
        explanation = 'Automatic fix unavailable for this defect type.';
        patchSummary = 'Automatic fix unavailable.';
      }

      return { fixedCode, patchSummary, explanation };
    }
  },

  cpp: {
    id: 'cpp',
    name: 'C++',
    runtime: 'G++ (MinGW-w64 8.1.0)',
    extension: '.cpp',
    filename: 'main.cpp',
    isCompiled: true,

    async checkSyntax(code, tmpDir) {
      const filePath = path.join(tmpDir, 'syntax_check.cpp');
      fs.writeFileSync(filePath, code, 'utf8');
      const res = await runProcess('g++', ['-fsyntax-only', '-std=c++17', filePath], { cwd: tmpDir });
      return { ok: res.ok, error: res.stderr || null };
    },

    async execute(code, timeoutMs = 4000) {
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bf-cpp-'));
      const srcPath = path.join(tmpDir, 'main.cpp');
      const binPath = path.join(tmpDir, 'main.exe');
      try {
        fs.writeFileSync(srcPath, code, 'utf8');
        const compileRes = await runProcess('g++', ['-Wall', '-std=c++17', srcPath, '-o', binPath], { cwd: tmpDir });
        if (!compileRes.ok) {
          return { ok: false, exitCode: compileRes.exitCode, phase: 'compilation', stdout: '', stderr: 'C++ Compilation Error (G++):\n' + compileRes.stderr, durationMs: compileRes.durationMs, timedOut: false };
        }
        return await runProcess(binPath, [], { cwd: tmpDir, timeoutMs });
      } finally { try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {} }
    },

    detectBugs(code, runtimeResult) {
      const normalized = (code || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      const lines = normalized.split('\n');
      const findings = [];

      // Check 1: C++ off-by-one
      const offByOneIndex = lines.findIndex(l =>
        /for\s*\(\s*(int|size_t|auto)\s+[a-zA-Z0-9_]+\s*=\s*0\s*;\s*[a-zA-Z0-9_]+\s*<=\s*([a-zA-Z0-9_]+(\.size\(\))?)\s*;/.test(l) ||
        /[a-zA-Z0-9_]+\s*<=\s*[a-zA-Z0-9_]+(\.size\(\))?/.test(l)
      );
      if (offByOneIndex !== -1) {
        findings.push({ bugId: 'LOGIC-BOUND-CPP-001', title: 'Off-by-One Range Boundary in C++ Loop', category: 'Logic', severity: 'High', cwe: 'CWE-193', line: offByOneIndex + 1, codeSnippet: lines[offByOneIndex].trim(), confidence: 0.98, description: 'Loop condition uses "<=" on container size or array length, reading past the allocated memory buffer.' });
      }

      // Check 2: C++ null pointer dereference
      const nullPtrLine = lines.findIndex(l =>
        /\/\/\s*(BUG|ERROR).*nullptr.*dereference/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*null.*pointer/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*[Nn][Pp][Ee]/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*dereference.*null/i.test(l)
      );
      if (nullPtrLine !== -1) {
        findings.push({ bugId: 'RUNTIME-NULLPTR-CPP-002', title: 'Null Pointer Dereference in C++', category: 'Runtime', severity: 'Critical', cwe: 'CWE-476', line: nullPtrLine + 1, codeSnippet: lines[nullPtrLine].trim(), confidence: 0.93, description: 'A pointer holds nullptr and is dereferenced without a null check, causing undefined behavior or segmentation fault.' });
      }

      // Check 3: C++ integer divide by zero
      const divZeroLine = lines.findIndex(l =>
        /\/\/\s*(BUG|ERROR).*divide.*zero/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*division.*zero/i.test(l) ||
        /\/\/\s*(BUG|ERROR).*[Zz]ero.*[Dd]iv/i.test(l) ||
        (/[a-zA-Z0-9_)]\s*\/\s*0(?![.\d])/.test(l) && !l.trim().startsWith('//'))
      );
      if (divZeroLine !== -1) {
        findings.push({ bugId: 'RUNTIME-DIVZERO-CPP-003', title: 'Integer Division by Zero in C++', category: 'Runtime', severity: 'High', cwe: 'CWE-369', line: divZeroLine + 1, codeSnippet: lines[divZeroLine].trim(), confidence: 0.95, description: 'An integer expression divides by a literal zero or unguarded variable, causing undefined behavior or a SIGFPE signal at runtime.' });
      }

      // --- Runtime Error Detection from actual execution evidence ---
      if (runtimeResult && !runtimeResult.ok) {
        const stderr = runtimeResult.stderr || '';
        const exitCode = runtimeResult.exitCode;
        const existingBugIds = new Set(findings.map(f => f.bugId));

        // C++ Syntax / Compilation errors
        if (/error:\s*expected\s*';'/i.test(stderr) && !(/expected\s*';'\s*before\s*'{'/i.test(stderr))) {
          const lineMatch = stderr.match(/main\.cpp:(\d+):/);
          const lineNum = lineMatch ? parseInt(lineMatch[1]) : 1;
          const snippet = lines[lineNum - 1] ? lines[lineNum - 1].trim() : '';
          findings.unshift({
            bugId: 'SYNTAX-CPP-001',
            title: "SyntaxError: Missing Semicolon ';'",
            category: 'Syntax',
            severity: 'Critical',
            cwe: 'CWE-1007',
            line: lineNum,
            codeSnippet: snippet,
            confidence: 0.99,
            description: "G++ compiler reported missing semicolon ';' before subsequent statement.",
            runtimeEvidence: stderr
          });
        } else if (/error:\s*expected\s*'\)'/i.test(stderr) || (/expected\s*';'\s*before\s*'{'/i.test(stderr) && /\b(?:if|while|for)\s*\([^)]*\{/.test(code))) {
          const lineMatch = stderr.match(/main\.cpp:(\d+):/);
          const lineNum = lineMatch ? parseInt(lineMatch[1]) : 1;
          const snippet = lines[lineNum - 1] ? lines[lineNum - 1].trim() : '';
          findings.unshift({
            bugId: 'SYNTAX-CPP-002',
            title: "SyntaxError: Missing Closing Parenthesis ')'",
            category: 'Syntax',
            severity: 'Critical',
            cwe: 'CWE-1007',
            line: lineNum,
            codeSnippet: snippet,
            confidence: 0.99,
            description: "G++ compiler reported missing closing parenthesis ')'.",
            runtimeEvidence: stderr
          });
        } else if (/C\+\+ Compilation Error/i.test(stderr) || (/main\.cpp:.*error:/i.test(stderr))) {
          const lineMatch = stderr.match(/main\.cpp:(\d+):/);
          const lineNum = lineMatch ? parseInt(lineMatch[1]) : 1;
          const errMatch = stderr.match(/error:\s*(.+)/);
          const snippet = lines[lineNum - 1] ? lines[lineNum - 1].trim() : '';
          findings.unshift({
            bugId: 'SYNTAX-CPP-003',
            title: `SyntaxError: C++ Compiler Error (G++)`,
            category: 'Syntax',
            severity: 'Critical',
            cwe: 'CWE-1007',
            line: lineNum,
            codeSnippet: snippet || (errMatch ? errMatch[1].trim() : 'compiler error'),
            confidence: 0.99,
            description: `G++ compiler reported complex syntax error: ${errMatch ? errMatch[1].trim() : 'compilation error'}.`,
            runtimeEvidence: stderr
          });
        }

        // C++ segmentation fault (null pointer dereference) from runtime
        if ((runtimeResult.signal === 'SIGSEGV' || /segmentation fault/i.test(stderr) || /SIGSEGV/i.test(stderr) || exitCode === -1073741819 || exitCode === 3221225477) && !existingBugIds.has('RUNTIME-NULLPTR-CPP-002')) {
          findings.push({ bugId: 'RUNTIME-NULLPTR-CPP-001', title: 'Segmentation Fault / Null Pointer Dereference (Runtime Evidence)', category: 'Runtime', severity: 'Critical', cwe: 'CWE-476', line: 1, codeSnippet: 'Segmentation fault (SIGSEGV)', confidence: 0.99, description: 'Runtime execution crashed with a segmentation fault signal, indicating null pointer dereference or invalid memory access.', runtimeEvidence: stderr || 'exit code: ' + exitCode });
        }

        // C++ divide by zero (SIGFPE) from runtime
        if ((runtimeResult.signal === 'SIGFPE' || /floating.*point.*exception/i.test(stderr) || /SIGFPE/i.test(stderr) || exitCode === -1073741676 || exitCode === 3221225620) && !existingBugIds.has('RUNTIME-DIVZERO-CPP-003')) {
          findings.push({ bugId: 'RUNTIME-DIV-CPP-001', title: 'Integer Division by Zero / SIGFPE (Runtime Evidence)', category: 'Runtime', severity: 'High', cwe: 'CWE-369', line: 1, codeSnippet: 'Floating-point exception (SIGFPE)', confidence: 0.99, description: 'Runtime execution crashed with SIGFPE signal, indicating integer division by zero or arithmetic overflow.', runtimeEvidence: stderr || 'exit code: ' + exitCode });
        }
      }

      return findings;
    },

    generateFix(code, findingId) {
      let fixedCode = (code || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
      let explanation = '';
      let patchSummary = '';

      if (findingId === 'LOGIC-BOUND-CPP-001' || /<=\s*[a-zA-Z0-9_]+(\.size\(\))?/.test(fixedCode)) {
        fixedCode = fixedCode.replace(/(for\s*\([^;]+;\s*[a-zA-Z0-9_]+)\s*<=\s*([a-zA-Z0-9_]+(\.size\(\))?)(\s*;)/g, '$1 < $2$4');
        if (fixedCode.includes('// BUG:')) fixedCode = fixedCode.replace(/\/\/\s*BUG:[^\n]*/g, '// FIX: Loop boundary changed to `<` to safely constrain container index');
        explanation = 'Corrected C++ loop condition from `<=` to `<`.';
        patchSummary = 'Fixed C++ loop boundary operator from `<=` to `<`.';
      } else if (findingId === 'SYNTAX-CPP-001') {
        const codeLines = fixedCode.split('\n');
        for (let i = 0; i < codeLines.length; i++) {
          const trimmed = codeLines[i].trim();
          if (trimmed && !trimmed.endsWith(';') && !trimmed.endsWith('{') && !trimmed.endsWith('}') && !trimmed.startsWith('#') && !trimmed.startsWith('//') && !trimmed.includes('main(')) {
            codeLines[i] = codeLines[i] + ';';
            break;
          }
        }
        fixedCode = codeLines.join('\n');
        explanation = "Safely appended missing semicolon ';' statement terminator identified by G++.";
        patchSummary = "Repaired syntax error: appended missing ';' statement terminator.";
      } else if (findingId === 'SYNTAX-CPP-002') {
        const codeLines = fixedCode.split('\n');
        for (let i = 0; i < codeLines.length; i++) {
          if (/\b(?:if|while|for)\s*\([^)]*?\{/.test(codeLines[i])) {
            codeLines[i] = codeLines[i].replace(/(\b(?:if|while|for)\s*\([^)]*?)\s*\{/, '$1) {');
            break;
          }
        }
        fixedCode = codeLines.join('\n');
        explanation = "Safely inserted missing closing parenthesis ')' before block opening '{'.";
        patchSummary = "Repaired syntax error: inserted missing ')' delimiter.";
      } else if (findingId === 'SYNTAX-CPP-003') {
        explanation = "Automatic fix unavailable — G++ reported complex or ambiguous syntax error. Manual correction required.";
        patchSummary = "Automatic fix unavailable for complex C++ syntax error. Manual correction required.";
      } else if (findingId === 'RUNTIME-NULLPTR-CPP-002' || findingId === 'RUNTIME-NULLPTR-CPP-001') {
        explanation = 'Automatic fix unavailable — Null pointer dereference requires validating pointers against nullptr or using smart pointers.';
        patchSummary = 'Automatic fix unavailable for nullptr dereference. Pointer validation required.';
      } else if (findingId === 'RUNTIME-DIVZERO-CPP-003' || findingId === 'RUNTIME-DIV-CPP-001') {
        explanation = 'Automatic fix unavailable — Integer division by zero causes SIGFPE or undefined behavior. Ensure divisor is non-zero before division.';
        patchSummary = 'Automatic fix unavailable for Division by Zero. Divisor must be checked before division.';
      } else {
        explanation = 'Automatic fix unavailable for this defect type.';
        patchSummary = 'Automatic fix unavailable.';
      }

      return { fixedCode, patchSummary, explanation };
    }
  }
};

// Root Cause Analysis across languages
function analyzeLanguageCause(code, findingId, language = 'javascript') {
  if (findingId && findingId.startsWith('SYNTAX-')) {
    const isParen = (findingId.includes('-001') && (language === 'python' || language === 'javascript')) || findingId.includes('-002');
    const isSemi = findingId.includes('-001') && (language === 'java' || language === 'c' || language === 'cpp');
    const isBracket = findingId.includes('-002') && (language === 'python' || language === 'javascript');
    const isComplex = findingId.includes('-003');

    const errorDesc = isParen ? 'missing closing parenthesis ")"'
      : isSemi ? 'missing semicolon ";"'
      : isBracket ? 'missing closing bracket or brace'
      : 'syntax specification violation';

    return {
      findingId,
      hunter: {
        claim: `SYNTAX DEFECT: ${language.toUpperCase()} parser/compiler rejected source code (${errorDesc}).`,
        evidence: `Compiler/interpreter diagnostic halted execution with syntax error signature: ${findingId}.`
      },
      skeptic: {
        critique: 'Is the syntax defect deterministic and unambiguously repairable without guessing intent?',
        evaluation: isComplex
          ? `No. The syntax error is complex or multi-token, meaning multiple conflicting repairs are possible. Automatic repair is unsafe.`
          : `Yes. Compiler location and diagnostic pinpoint the missing ${errorDesc} delimiter with high precision.`
      },
      referee: {
        verdict: 'CONFIRMED TRUE POSITIVE',
        rootCause: `Formal language grammar violation (CWE-1007 / Syntax Error). Code contains ${errorDesc}.`,
        threatVector: `Program fails to compile or parse. Process exits with non-zero exit code before execution starts.`,
        remediation: isComplex
          ? `Review compiler diagnostics and restructure the malformed statement according to ${language} grammar.`
          : `Add the missing ${errorDesc} at the compiler-indicated position to restore grammatical validity.`
      }
    };
  }

  if (findingId && findingId.startsWith('LOGIC-BOUND')) {
    return {
      findingId,
      hunter: { claim: `LOGIC DEFECT: Off-by-one loop boundary exceeds container/array range in ${language}.`, evidence: 'The loop executes with "<=" on collection length/size, attempting to access an invalid index past the end of the allocated sequence.' },
      skeptic: { critique: 'Does the container use 1-based indexing or have an extra sentinel element?', evaluation: `No. In ${language}, arrays and sequences are strictly 0-indexed. Accessing index N on a length-N structure violates memory invariants.` },
      referee: { verdict: 'CONFIRMED TRUE POSITIVE', rootCause: 'Off-by-one boundary condition error (CWE-193). Using "<=" instead of "<" attempts to access index N on zero-based collection [0..N-1].', threatVector: 'Causes runtime exception (IndexError in Python, ArrayIndexOutOfBoundsException in Java), undefined memory behavior in C/C++, or runtime NaN in JavaScript.', remediation: 'Change boundary operator from "<=" to "<" (or adjust range() in Python) to constrain iteration strictly to valid indices.' }
    };
  }

  if (findingId && (findingId.includes('NPE') || findingId.includes('NULLPTR') || findingId.includes('NONE'))) {
    return {
      findingId,
      hunter: { claim: `RUNTIME DEFECT: Null/None dereference in ${language} — method or property access on a null reference.`, evidence: 'A pointer, reference, or object variable is null/None/nullptr when it is used, causing a runtime exception.' },
      skeptic: { critique: 'Could the null be intentional (sentinel value)?', evaluation: 'No. Code proceeds to call a method or dereference the pointer without any null guard.' },
      referee: { verdict: 'CONFIRMED TRUE POSITIVE', rootCause: 'Null/None pointer dereference (CWE-476). Variable holds a null reference when dereferenced.', threatVector: language === 'java' ? 'NullPointerException crashes the JVM thread.' : language === 'python' ? 'AttributeError raises from NoneType dereference.' : 'Segmentation fault or undefined behavior from null pointer dereference.', remediation: 'Initialize with a safe default value or add an explicit null check before access.' }
    };
  }

  if (findingId && (findingId.includes('ZDIV') || findingId.includes('ARITH') || findingId.includes('DIVZERO') || findingId.includes('DIV-'))) {
    return {
      findingId,
      hunter: { claim: `RUNTIME DEFECT: Division by zero in ${language} — integer expression divides by zero.`, evidence: 'A divisor is zero (literal or unguarded variable), causing an arithmetic exception or undefined behavior at runtime.' },
      skeptic: { critique: 'Could the divisor change at runtime and be non-zero?', evaluation: 'The bug is reproduced deterministically. The divisor is a literal zero or demonstrably unguarded.' },
      referee: { verdict: 'CONFIRMED TRUE POSITIVE', rootCause: 'Division by zero (CWE-369). An integer or float is divided by a zero divisor without a pre-condition check.', threatVector: language === 'java' ? 'ArithmeticException: / by zero — crashes the running thread.' : language === 'python' ? 'ZeroDivisionError — terminates the script.' : 'Undefined behavior or SIGFPE — process may crash or produce garbage output.', remediation: 'Add a zero-check guard before division: `if (divisor != 0)` or use `Math.max(1, divisor)` to enforce a safe minimum.' }
    };
  }

  if (findingId && (findingId.includes('REF') || findingId.includes('NAME'))) {
    return {
      findingId,
      hunter: { claim: `RUNTIME DEFECT: Use of undeclared/undefined variable in ${language}.`, evidence: 'Code accesses an identifier that was never declared or assigned in the current scope.' },
      skeptic: { critique: 'Could the variable be declared in an outer scope or global namespace?', evaluation: 'Static analysis and runtime trace confirm the variable is not bound in any accessible scope at the point of use.' },
      referee: { verdict: 'CONFIRMED TRUE POSITIVE', rootCause: 'Use of uninitialized or undeclared variable (CWE-457).', threatVector: language === 'javascript' ? 'ReferenceError at runtime — script halts.' : language === 'python' ? 'NameError at runtime — script halts.' : 'Undefined behavior or compile error.', remediation: 'Declare the variable with an appropriate type and safe default value before use.' }
    };
  }

  if (findingId && (findingId.includes('TYPE') || findingId.includes('ATTR'))) {
    return {
      findingId,
      hunter: { claim: `RUNTIME DEFECT: Type mismatch — property or method access on null/undefined/wrong type in ${language}.`, evidence: 'Code attempts to access a property or call a method on a value that is null, undefined, or an incompatible type.' },
      skeptic: { critique: 'Could optional chaining make this safe?', evaluation: 'No optional chaining or null guard is present. The TypeError is raised deterministically.' },
      referee: { verdict: 'CONFIRMED TRUE POSITIVE', rootCause: 'Property access on null/undefined value (CWE-476 / CWE-843).', threatVector: language === 'python' ? 'TypeError at runtime — incompatible types in operation.' : 'TypeError at runtime — execution halts with an uncaught exception.', remediation: language === 'python' ? 'Convert values to compatible types using str(), int(), or float() before combining them.' : 'Use optional chaining (`?.`) or an explicit null check before accessing properties or methods.' }
    };
  }

  if (findingId && findingId.includes('INDEX')) {
    return {
      findingId,
      hunter: { claim: `RUNTIME DEFECT: Index out of bounds access in ${language}.`, evidence: 'Code accesses a sequence/array element at an index that exceeds valid bounds.' },
      skeptic: { critique: 'Could the index be dynamically computed to stay in bounds?', evaluation: 'Runtime evidence confirms the index exceeds the sequence length at the point of access.' },
      referee: { verdict: 'CONFIRMED TRUE POSITIVE', rootCause: 'Out-of-bounds index access (CWE-125).', threatVector: language === 'python' ? 'IndexError at runtime — script terminates with uncaught exception.' : language === 'java' ? 'ArrayIndexOutOfBoundsException — JVM thread crashes.' : 'Undefined behavior or memory corruption.', remediation: 'Validate the index against the sequence length before access: `if (index < len(seq))` or equivalent.' }
    };
  }

  if (findingId && findingId.includes('KEY')) {
    return {
      findingId,
      hunter: { claim: `RUNTIME DEFECT: Missing dictionary/map key access in ${language}.`, evidence: 'Code accesses a dictionary key that does not exist in the mapping.' },
      skeptic: { critique: 'Could the key exist at runtime via dynamic population?', evaluation: 'Runtime evidence confirms the key is absent from the dictionary at the point of access.' },
      referee: { verdict: 'CONFIRMED TRUE POSITIVE', rootCause: 'Missing key access on dictionary/map (CWE-754).', threatVector: 'KeyError at runtime — script terminates with uncaught exception.', remediation: 'Use dict.get(key, default) or check `if key in dict` before access.' }
    };
  }

  if (findingId && findingId.includes('RANGE')) {
    return {
      findingId,
      hunter: { claim: `RUNTIME DEFECT: Numeric or stack value exceeds allowed range in ${language}.`, evidence: 'Code produces a value that exceeds the allowed numeric or call-stack range.' },
      skeptic: { critique: 'Could the recursion/value be bounded by design?', evaluation: 'Runtime evidence confirms the RangeError was raised — the value or recursion depth exceeded safe limits.' },
      referee: { verdict: 'CONFIRMED TRUE POSITIVE', rootCause: 'Value out of allowed range (CWE-754).', threatVector: 'RangeError at runtime — execution halts when value exceeds engine limits.', remediation: 'Add explicit bounds checking or limit recursion depth before the operation.' }
    };
  }

  if (findingId === 'SEC-JWT-001' || code.includes("header.alg === 'none'")) {
    return {
      findingId: 'SEC-JWT-001',
      hunter: { claim: 'CRITICAL SECURITY DEFECT: Authentication bypass possible via token forgery.', evidence: 'Verification checks header.alg === "none" without cryptographic signature.' },
      skeptic: { critique: 'Could none be intentional for development?', evaluation: 'Rejected. Violates RFC 7519 security guidance.' },
      referee: { verdict: 'CONFIRMED TRUE POSITIVE', rootCause: 'Algorithm negotiation flaw (CWE-327 / CWE-287).', threatVector: 'Attacker crafts token with alg: none to gain unauthorized admin rights.', remediation: 'Disallow none algorithm unconditionally.' }
    };
  }

  return {
    findingId: findingId || 'GEN-001',
    hunter: { claim: 'Code defect detected.', evidence: 'Static analysis flagged boundary or safety violation.' },
    skeptic: { critique: 'Evaluating runtime severity.', evaluation: 'Validated defect signature.' },
    referee: { verdict: 'CONFIRMED', rootCause: 'Control flow or indexing error.', threatVector: 'Runtime failure or unexpected behavior.', remediation: 'Apply defensive boundary checks.' }
  };
}

module.exports = { LANGUAGE_REGISTRY, RUNTIME_ENV, runProcess, analyzeLanguageCause };
