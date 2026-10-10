#!/usr/bin/env node
// Comprehensive Syntax Error Detection & Safe Auto-Fix Test Suite
// Tests all 5 supported languages: Python, JavaScript, Java, C, C++
// Covers both safely auto-fixable syntax errors and manual non-deterministic errors.
const http = require('http');

const BASE = 'http://localhost:3000';

function request(path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const url = new URL(path, BASE);
    const req = http.request(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }
    }, (res) => {
      let chunks = '';
      res.on('data', c => chunks += c);
      res.on('end', () => {
        try { resolve(JSON.parse(chunks)); }
        catch (e) { reject(new Error('Invalid JSON: ' + chunks.substring(0, 200))); }
      });
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

const results = [];

async function testSyntaxCase(name, language, code, expectedBugIdPattern, expectAutoFix = true) {
  const result = { name, language, expectAutoFix, run: 'SKIP', detect: 'FAIL', cause: 'FAIL', fix: 'SKIP', verify: 'SKIP' };

  try {
    // Step 1: Run buggy code — should fail due to syntax/compilation error
    const runRes = await request('/api/run', { code, language });
    result.run = (runRes.ok === false || runRes.exitCode !== 0) ? 'PASS' : 'FAIL';
    result.runExitCode = runRes.exitCode;

    // Step 2: Detect Bug — must identify syntax error from compiler/interpreter output
    const detectRes = await request('/api/detect', { code, language });
    const findings = detectRes.findings || [];
    const matched = findings.find(f => f.bugId.match(new RegExp(expectedBugIdPattern)));
    result.detect = matched ? 'PASS' : 'FAIL';
    result.detectedBugIds = findings.map(f => f.bugId);
    result.matchedCategory = matched ? matched.category : null;

    if (!matched) {
      result.note = `Expected pattern /${expectedBugIdPattern}/ not found in: [${findings.map(f => f.bugId).join(', ')}]`;
      results.push(result);
      return result;
    }

    // Step 3: Cause Analysis
    const causeRes = await request('/api/cause', { code, findingId: matched.bugId, language });
    result.cause = (causeRes.cause && causeRes.cause.referee && causeRes.cause.referee.verdict) ? 'PASS' : 'FAIL';

    // Step 4: Fix Generation
    const fixRes = await request('/api/fix', { code, findingId: matched.bugId, language });
    const isUnavailable = fixRes.patchSummary && fixRes.patchSummary.toLowerCase().includes('unavailable');

    if (expectAutoFix) {
      if (fixRes.fixedCode && !isUnavailable) {
        result.fix = 'PASS';
        result.fixedCode = fixRes.fixedCode;
      } else {
        result.fix = 'FAIL';
        result.fixNote = fixRes.patchSummary;
      }
    } else {
      // Manual case: MUST report unavailable honestly!
      if (isUnavailable) {
        result.fix = 'PASS (MANUAL)';
        result.fixNote = fixRes.patchSummary;
      } else {
        result.fix = 'FAIL (Falsely claimed auto-fix)';
      }
    }

    // Step 5: Verification (Run fixed code and verify)
    if (expectAutoFix && result.fix === 'PASS') {
      const verifyRes = await request('/api/verify', { fixedCode: fixRes.fixedCode, language });
      result.verify = verifyRes.verified ? 'PASS' : 'FAIL';
      if (!verifyRes.verified && verifyRes.checks) {
        result.verifyDetails = verifyRes.checks.filter(c => !c.passed).map(c => c.name + ': ' + c.detail);
      }
    } else {
      result.verify = 'N/A';
    }
  } catch (err) {
    result.error = err.message;
  }

  results.push(result);
  return result;
}

async function main() {
  console.log('='.repeat(75));
  console.log('  SYNTAX ERROR DETECTION & REPAIR TEST SUITE');
  console.log('  Testing: All 5 languages (Auto-Fixable + Manual Non-Deterministic)');
  console.log('='.repeat(75));
  console.log();

  // ===== PYTHON SYNTAX TESTS =====
  console.log('--- PYTHON SYNTAX ERRORS ---');

  // 1. Python missing ')' (auto-fixable)
  await testSyntaxCase(
    'Python Missing Parenthesis ")"',
    'python',
    `name = "Varshini"\nprint(name`,
    'SYNTAX-PY-001',
    true
  );

  // 2. Python missing ']' (auto-fixable)
  await testSyntaxCase(
    'Python Missing Bracket "]"',
    'python',
    `numbers = [10, 20, 30\nprint(numbers)`,
    'SYNTAX-PY-002',
    true
  );

  // 3. Python complex / manual syntax error
  await testSyntaxCase(
    'Python Complex Malformed Syntax (Manual)',
    'python',
    `def : invalid_func\n    pass`,
    'SYNTAX-PY-003',
    false
  );

  // ===== JAVASCRIPT SYNTAX TESTS =====
  console.log('\n--- JAVASCRIPT SYNTAX ERRORS ---');

  // 1. JS missing ')' (auto-fixable)
  await testSyntaxCase(
    'JavaScript Missing Parenthesis ")"',
    'javascript',
    `function greet() {\n  console.log("Hello";\n}\ngreet();`,
    'SYNTAX-JS-001',
    true
  );

  // 2. JS missing '}' (auto-fixable)
  await testSyntaxCase(
    'JavaScript Missing Brace "}"',
    'javascript',
    `function greet() {\n  console.log("Hello");\n`,
    'SYNTAX-JS-002',
    true
  );

  // 3. JS complex / manual syntax error
  await testSyntaxCase(
    'JavaScript Non-Deterministic Syntax (Manual)',
    'javascript',
    `let = ;\nconsole.log(123);`,
    'SYNTAX-JS-003',
    false
  );

  // ===== JAVA SYNTAX TESTS =====
  console.log('\n--- JAVA SYNTAX ERRORS ---');

  // 1. Java missing ';' (auto-fixable)
  await testSyntaxCase(
    'Java Missing Semicolon ";"',
    'java',
    `public class Main {\n  public static void main(String[] args) {\n    System.out.println("Hello")\n  }\n}`,
    'SYNTAX-JAVA-001',
    true
  );

  // 2. Java missing ')' (auto-fixable)
  await testSyntaxCase(
    'Java Missing Parenthesis ")"',
    'java',
    `public class Main {\n  public static void main(String[] args) {\n    if (5 > 3 {\n      System.out.println("Yes");\n    }\n  }\n}`,
    'SYNTAX-JAVA-002',
    true
  );

  // 3. Java complex / manual syntax error
  await testSyntaxCase(
    'Java Malformed Declaration (Manual)',
    'java',
    `public class Main {\n  public static void main(String[] args) {\n    int x = ;\n  }\n}`,
    'SYNTAX-JAVA-003',
    false
  );

  // ===== C SYNTAX TESTS =====
  console.log('\n--- C SYNTAX ERRORS ---');

  // 1. C missing ';' (auto-fixable)
  await testSyntaxCase(
    'C Missing Semicolon ";"',
    'c',
    `#include <stdio.h>\nint main() {\n  printf("Hello\\n")\n  return 0;\n}`,
    'SYNTAX-C-001',
    true
  );

  // 2. C missing ')' (auto-fixable)
  await testSyntaxCase(
    'C Missing Parenthesis ")"',
    'c',
    `#include <stdio.h>\nint main() {\n  if (5 > 3 {\n    printf("Yes\\n");\n  }\n  return 0;\n}`,
    'SYNTAX-C-002',
    true
  );

  // 3. C complex / manual syntax error
  await testSyntaxCase(
    'C Malformed Syntax (Manual)',
    'c',
    `#include <stdio.h>\nint main() {\n  int = ;\n  return 0;\n}`,
    'SYNTAX-C-003',
    false
  );

  // ===== C++ SYNTAX TESTS =====
  console.log('\n--- C++ SYNTAX ERRORS ---');

  // 1. C++ missing ';' (auto-fixable)
  await testSyntaxCase(
    'C++ Missing Semicolon ";"',
    'cpp',
    `#include <iostream>\nint main() {\n  std::cout << "Hello" << std::endl\n  return 0;\n}`,
    'SYNTAX-CPP-001',
    true
  );

  // 2. C++ missing ')' (auto-fixable)
  await testSyntaxCase(
    'C++ Missing Parenthesis ")"',
    'cpp',
    `#include <iostream>\nint main() {\n  if (5 > 3 {\n    std::cout << "Yes" << std::endl;\n  }\n  return 0;\n}`,
    'SYNTAX-CPP-002',
    true
  );

  // 3. C++ complex / manual syntax error
  await testSyntaxCase(
    'C++ Malformed Syntax (Manual)',
    'cpp',
    `#include <iostream>\nint main() {\n  int = ;\n  return 0;\n}`,
    'SYNTAX-CPP-003',
    false
  );

  // ===== RESULTS =====
  console.log('\n' + '='.repeat(75));
  console.log('  SYNTAX TEST RESULTS SUMMARY');
  console.log('='.repeat(75));

  let passedTests = 0;
  let failedTests = 0;

  for (const r of results) {
    const isSuccess = r.detect === 'PASS' && r.cause === 'PASS' &&
      (r.expectAutoFix ? (r.fix === 'PASS' && r.verify === 'PASS') : (r.fix.startsWith('PASS')));

    const statusIcon = isSuccess ? '✅' : '❌';

    console.log(`\n  [${r.language.toUpperCase().padEnd(6)}] ${r.name}`);
    console.log(`    Run (Failed): ${r.run} | Detect: ${r.detect} | Cause: ${r.cause} | Fix: ${r.fix} | Verify: ${r.verify}  ${statusIcon}`);
    if (r.detectedBugIds) console.log(`    Bug IDs: [${r.detectedBugIds.join(', ')}] (Category: ${r.matchedCategory})`);
    if (r.fixNote) console.log(`    Fix Note: ${r.fixNote}`);
    if (r.verifyDetails) console.log(`    Verify Issues: ${r.verifyDetails.join('; ')}`);
    if (r.note) console.log(`    NOTE: ${r.note}`);
    if (r.error) console.log(`    ERROR: ${r.error}`);

    if (isSuccess) passedTests++;
    else failedTests++;
  }

  console.log('\n' + '-'.repeat(75));
  console.log(`  TOTAL: ${results.length} tests  |  ${passedTests} PASSED  |  ${failedTests} FAILED`);
  console.log('-'.repeat(75));

  if (failedTests > 0) {
    console.log('\n  ⚠️  Some syntax tests failed.');
    process.exit(1);
  } else {
    console.log('\n  ✅ All syntax tests passed successfully!');
    process.exit(0);
  }
}

main().catch(err => {
  console.error('Syntax test suite error:', err);
  process.exit(1);
});
