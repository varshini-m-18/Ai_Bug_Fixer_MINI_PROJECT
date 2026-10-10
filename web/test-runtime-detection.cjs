#!/usr/bin/env node
// Comprehensive Runtime Error Detection Test Suite
// Tests existing off-by-one bugs (regression) + all new runtime error types
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

async function testCase(name, language, code, expectedBugIdPattern, expectFix = false) {
  const result = { name, language, run: 'SKIP', detect: 'FAIL', cause: 'FAIL', fix: 'SKIP', verify: 'SKIP' };

  try {
    // Step 1: Run Code
    const runRes = await request('/api/run', { code, language });
    result.run = runRes.exitCode !== undefined ? 'PASS' : 'FAIL';

    // Step 2: Detect
    const detectRes = await request('/api/detect', { code, language });
    const findings = detectRes.findings || [];
    const matched = findings.find(f => f.bugId.match(new RegExp(expectedBugIdPattern)));
    result.detect = matched ? 'PASS' : 'FAIL';
    result.detectedBugIds = findings.map(f => f.bugId);

    if (!matched) {
      result.note = `Expected pattern /${expectedBugIdPattern}/ not found in: [${findings.map(f => f.bugId).join(', ')}]`;
      results.push(result);
      return result;
    }

    // Step 3: Cause Analysis
    const causeRes = await request('/api/cause', { code, findingId: matched.bugId, language });
    result.cause = causeRes.cause && causeRes.cause.referee && causeRes.cause.referee.verdict ? 'PASS' : 'FAIL';

    // Step 4: Fix
    const fixRes = await request('/api/fix', { code, findingId: matched.bugId, language });
    if (fixRes.fixedCode) {
      if (fixRes.patchSummary && fixRes.patchSummary.includes('unavailable')) {
        result.fix = 'NOT AVAILABLE';
        result.fixNote = fixRes.patchSummary;
      } else {
        result.fix = 'PASS';
      }
    } else {
      result.fix = 'FAIL';
    }

    // Step 5: Verify (only if a real fix was generated)
    if (result.fix === 'PASS' && fixRes.fixedCode) {
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
  console.log('='.repeat(70));
  console.log('  COMPREHENSIVE BUG DETECTION TEST SUITE');
  console.log('  Testing: Regression (off-by-one) + New Runtime Errors');
  console.log('='.repeat(70));
  console.log();

  // ===== REGRESSION TESTS: Off-by-one / Boundary =====
  console.log('--- REGRESSION: Off-by-One / Boundary Detection ---');

  await testCase('Python Off-by-One', 'python',
    `numbers = [10, 20, 30, 40]\nfor i in range(0, len(numbers) + 1):\n    print(numbers[i])`,
    'LOGIC-BOUND-PY', true);

  await testCase('JavaScript Off-by-One', 'javascript',
    `const arr = [1,2,3];\nfor (let i = 0; i <= arr.length; i++) { console.log(arr[i]); }`,
    'LOGIC-BOUND-003', true);

  await testCase('Java Off-by-One', 'java',
    `public class Main {\n  public static void main(String[] args) {\n    int[] numbers = {10, 20, 30};\n    for (int i = 0; i <= numbers.length; i++) {\n      System.out.println(numbers[i]);\n    }\n  }\n}`,
    'LOGIC-BOUND-JAVA', true);

  await testCase('C Off-by-One', 'c',
    `#include <stdio.h>\nint main() {\n  int numbers[4] = {10,20,30,40};\n  int n = 4;\n  for (int i = 0; i <= n; i++) {\n    printf("%d\\n", numbers[i]);\n  }\n  return 0;\n}`,
    'LOGIC-BOUND-C', true);

  await testCase('C++ Off-by-One', 'cpp',
    `#include <iostream>\n#include <vector>\nint main() {\n  std::vector<int> numbers = {10,20,30,40};\n  int n = numbers.size();\n  for (int i = 0; i <= n; i++) {\n    std::cout << numbers[i] << std::endl;\n  }\n  return 0;\n}`,
    'LOGIC-BOUND-CPP', true);

  // ===== NEW: Python Runtime Errors =====
  console.log('\n--- NEW: Python Runtime Error Detection ---');

  await testCase('Python ZeroDivisionError', 'python',
    `a = 10\nb = 0\nprint(a / b)`,
    'RUNTIME-ZDIV-PY');

  await testCase('Python NameError', 'python',
    `numbers = [1, 2, 3]\nprint(numbrs)`,
    'RUNTIME-NAME-PY');

  await testCase('Python TypeError', 'python',
    `name = "Varshini"\nage = 19\nprint(name + age)`,
    'RUNTIME-TYPE-PY');

  await testCase('Python IndexError', 'python',
    `numbers = [10, 20, 30]\nprint(numbers[5])`,
    'RUNTIME-INDEX-PY');

  await testCase('Python KeyError', 'python',
    `student = {"name": "Varshini"}\nprint(student["marks"])`,
    'RUNTIME-KEY-PY');

  // ===== NEW: JavaScript Runtime Errors =====
  console.log('\n--- NEW: JavaScript Runtime Error Detection ---');

  await testCase('JavaScript ReferenceError', 'javascript',
    `console.log(username);`,
    'RUNTIME-REF-JS');

  await testCase('JavaScript TypeError', 'javascript',
    `let user = null;\nconsole.log(user.name);`,
    'RUNTIME-TYPE-JS');

  await testCase('JavaScript RangeError', 'javascript',
    `const arr = new Array(-1);`,
    'RUNTIME-RANGE-JS');

  // ===== NEW: Java Runtime Errors =====
  console.log('\n--- NEW: Java Runtime Error Detection ---');

  await testCase('Java NullPointerException', 'java',
    `public class Main {\n  public static void main(String[] args) {\n    String name = null;\n    System.out.println(name.length());\n  }\n}`,
    'RUNTIME-NPE-JAVA');

  await testCase('Java ArithmeticException', 'java',
    `public class Main {\n  public static void main(String[] args) {\n    int a = 10;\n    int b = 0;\n    System.out.println(a / b);\n  }\n}`,
    'RUNTIME-ARITH-JAVA');

  await testCase('Java ArrayIndexOutOfBounds', 'java',
    `public class Main {\n  public static void main(String[] args) {\n    int[] numbers = {10, 20, 30};\n    System.out.println(numbers[5]);\n  }\n}`,
    'RUNTIME-INDEX-JAVA');

  // ===== NEW: C Runtime Errors =====
  console.log('\n--- NEW: C Runtime Error Detection ---');

  await testCase('C Division by Zero', 'c',
    `#include <stdio.h>\nint main() {\n  int a = 10;\n  int b = 0;\n  printf("%d\\n", a / b);\n  return 0;\n}`,
    'RUNTIME-(DIVZERO|DIV)-C');

  // ===== NEW: C++ Runtime Errors =====
  console.log('\n--- NEW: C++ Runtime Error Detection ---');

  await testCase('C++ Division by Zero', 'cpp',
    `#include <iostream>\nusing namespace std;\nint main() {\n  int a = 10;\n  int b = 0;\n  cout << a / b << endl;\n  return 0;\n}`,
    'RUNTIME-(DIVZERO|DIV)-CPP');

  // ===== RESULTS =====
  console.log('\n' + '='.repeat(70));
  console.log('  TEST RESULTS SUMMARY');
  console.log('='.repeat(70));

  let passCount = 0;
  let failCount = 0;

  for (const r of results) {
    const detectStatus = r.detect === 'PASS' ? '✅' : '❌';
    const causeStatus = r.cause === 'PASS' ? '✅' : (r.detect === 'FAIL' ? '⏭️' : '❌');
    const fixStatus = r.fix === 'PASS' ? '✅' : (r.fix === 'NOT AVAILABLE' ? '⚠️' : (r.fix === 'N/A' || r.fix === 'SKIP' ? '⏭️' : '❌'));
    const verifyStatus = r.verify === 'PASS' ? '✅' : (r.verify === 'N/A' ? '⏭️' : '❌');

    console.log(`\n  [${r.language.toUpperCase().padEnd(6)}] ${r.name}`);
    console.log(`    Run: ${r.run}  |  Detect: ${r.detect} ${detectStatus}  |  Cause: ${r.cause} ${causeStatus}  |  Fix: ${r.fix} ${fixStatus}  |  Verify: ${r.verify} ${verifyStatus}`);
    if (r.detectedBugIds) console.log(`    Bug IDs: [${r.detectedBugIds.join(', ')}]`);
    if (r.note) console.log(`    NOTE: ${r.note}`);
    if (r.fixNote) console.log(`    Fix Note: ${r.fixNote}`);
    if (r.verifyDetails) console.log(`    Verify Issues: ${r.verifyDetails.join('; ')}`);
    if (r.error) console.log(`    ERROR: ${r.error}`);

    if (r.detect === 'PASS') passCount++;
    else failCount++;
  }

  console.log('\n' + '-'.repeat(70));
  console.log(`  TOTAL: ${results.length} tests  |  ${passCount} DETECTED  |  ${failCount} MISSED`);
  console.log('-'.repeat(70));

  if (failCount > 0) {
    console.log('\n  ⚠️  Some detections failed. Review the results above.');
    process.exit(1);
  } else {
    console.log('\n  ✅ All detections passed successfully!');
    process.exit(0);
  }
}

main().catch(err => {
  console.error('Test suite error:', err);
  process.exit(1);
});
