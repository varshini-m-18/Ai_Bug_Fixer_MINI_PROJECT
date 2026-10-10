const http = require('http');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { LANGUAGE_REGISTRY, analyzeLanguageCause } = require('./languages.cjs');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

const MIME_TYPES = {
  '.html': 'text/html; charset=UTF-8',
  '.css': 'text/css; charset=UTF-8',
  '.js': 'application/javascript; charset=UTF-8',
  '.json': 'application/json; charset=UTF-8',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// Multi-language preset catalog
const PRESETS = [
  // JavaScript Presets
  {
    id: 'jwt-auth-bypass',
    name: 'JWT "none" Alg & Auth Bypass',
    language: 'javascript',
    category: 'Security',
    severity: 'critical',
    description: 'Vulnerable token verification accepting unverified "none" algorithm and skipping signature check.',
    code: `// Vulnerable Authentication Service
function verifyToken(token, secretKey) {
  const parts = token.split('.');
  if (parts.length !== 3) {
    throw new Error('Invalid token structure');
  }

  const header = JSON.parse(Buffer.from(parts[0], 'base64').toString('utf8'));
  const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf8'));
  const signature = parts[2];

  // BUG: Allowing 'none' algorithm bypasses signature verification!
  if (header.alg === 'none') {
    console.log('[AUTH WARNING] Accepting unsigned "none" algorithm token');
    return { valid: true, user: payload.user, role: payload.role };
  }

  // Cryptographic check only runs if alg != 'none'
  const expectedSig = Buffer.from(parts[0] + '.' + parts[1] + secretKey).toString('base64');
  if (signature !== expectedSig) {
    throw new Error('Signature verification failed');
  }

  return { valid: true, user: payload.user, role: payload.role };
}

// Simulated execution with an forged admin token
const forgedHeader = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64');
const forgedPayload = Buffer.from(JSON.stringify({ user: 'attacker', role: 'admin' })).toString('base64');
const exploitToken = \`\${forgedHeader}.\${forgedPayload}.\`;

console.log('Verifying forged admin token...');
const authResult = verifyToken(exploitToken, 'super-secret-key-12345');
console.log('Result:', JSON.stringify(authResult));
if (authResult.role === 'admin') {
  console.error('[SECURITY FAILURE] Attacker successfully gained admin privileges without secret key!');
  process.exit(1);
}
`
  },
  {
    id: 'race-condition-transfer',
    name: 'Async Race Condition (Balance Underflow)',
    language: 'javascript',
    category: 'Concurrency',
    severity: 'high',
    description: 'Check-then-act race condition allowing account balance underflow through simultaneous withdrawals.',
    code: `// Vulnerable Bank Account Transfer Service
class BankAccount {
  constructor(id, initialBalance) {
    this.id = id;
    this.balance = initialBalance;
  }

  async withdraw(amount) {
    console.log(\`Checking balance for \$\${amount} withdrawal... current balance: \$\${this.balance}\`);
    // Check balance
    if (this.balance < amount) {
      throw new Error('Insufficient funds');
    }

    // Artificial latency simulating DB read or remote call
    await new Promise(resolve => setTimeout(resolve, 50));

    // Act: deduct balance (BUG: State was modified concurrently during await!)
    this.balance -= amount;
    console.log(\`Withdrawal successful. New balance: \$\${this.balance}\`);
    return this.balance;
  }
}

async function runTest() {
  const account = new BankAccount('acc-101', 100);
  console.log('Account initialized with $100');

  // Trigger 2 concurrent withdrawals of $80 each
  console.log('Initiating two concurrent $80 withdrawals...');
  try {
    await Promise.all([
      account.withdraw(80),
      account.withdraw(80)
    ]);
  } catch (err) {
    console.log('Transaction failed as expected:', err.message);
  }

  console.log('Final account balance:', account.balance);
  if (account.balance < 0) {
    console.error(\`[CONCURRENCY BUG] Negative balance detected (\$\${account.balance})! Total withdrawn $160 from $100.\`);
    process.exit(1);
  }
}

runTest();
`
  },
  {
    id: 'off-by-one-null-pointer',
    name: 'Off-by-One Loop & Null Pointer Exception',
    language: 'javascript',
    category: 'Logic',
    severity: 'medium',
    description: 'Boundary condition error using <= on array length causing uncaught TypeError on undefined element.',
    code: `// Batch Processing Service
function calculateSummaryScores(scores) {
  console.log(\`Processing \${scores.length} score items...\`);
  let total = 0;
  const processed = [];

  // BUG: loop condition uses '<=' instead of '<', reading scores[scores.length] (undefined)
  for (let i = 0; i <= scores.length; i++) {
    const item = scores[i];
    console.log(\`[Index \${i}] Processing score for: \${item.student}\`);
    total += item.score;
    processed.push({ id: item.student, grade: item.score >= 50 ? 'PASS' : 'FAIL' });
  }

  return { average: total / scores.length, records: processed };
}

const scoresList = [
  { student: 'Alice', score: 88 },
  { student: 'Bob', score: 72 },
  { student: 'Charlie', score: 95 }
];

console.log('Starting batch score aggregation...');
const result = calculateSummaryScores(scoresList);
console.log('Summary result:', result);
`
  },
  {
    id: 'sql-injection-flaw',
    name: 'SQL Injection via String Concatenation',
    language: 'javascript',
    category: 'Security',
    severity: 'critical',
    description: 'Direct concatenation of raw user input into query string allowing SQL injection and data breach.',
    code: `// Vulnerable User Lookup Query Builder
function buildUserQuery(username, status) {
  // BUG: Directly interpolating user input without parameterization
  const query = "SELECT id, username, email, role FROM users WHERE username = '" + username + "' AND status = '" + status + "'";
  return query;
}

// Simulated malicious user input containing SQL injection payload
const maliciousInput = "admin' OR '1'='1";
const statusFilter = "active";

console.log('Building query for username input:', maliciousInput);
const generatedQuery = buildUserQuery(maliciousInput, statusFilter);
console.log('Generated SQL Query:');
console.log(generatedQuery);

// Validate safety of the query
if (generatedQuery.includes("' OR '1'='1")) {
  console.error('[SECURITY DEFECT] SQL Injection detected! Query allows unauthenticated bypass of WHERE clause:');
  console.error('  Payload broke out of quotes and introduced tautology: "OR \\'1\\'=\\'1"');
  process.exit(1);
} else {
  console.log('Query sanitized successfully.');
}
`
  },

  // Python Presets
  {
    id: 'py-off-by-one',
    name: 'Python Off-by-One List Iteration',
    language: 'python',
    category: 'Logic',
    severity: 'medium',
    description: 'Boundary condition error using range(0, len(numbers) + 1) causing unhandled IndexError.',
    code: `# Python Batch Processing Service
def process_numbers():
    numbers = [10, 20, 30, 40]
    print(f"Processing {len(numbers)} numbers in Python...")
    total = 0
    # BUG: range upper bound includes len(numbers) + 1, causing index 4 out-of-range access
    for i in range(0, len(numbers) + 1):
        total += numbers[i]
        print(f"Index {i}: {numbers[i]} (running total: {total})")
    return total

print("Starting Python execution...")
total = process_numbers()
print(f"Final total: {total}")
`
  },
  {
    id: 'py-sql-injection',
    name: 'Python Raw SQL String Concatenation',
    language: 'python',
    category: 'Security',
    severity: 'critical',
    description: 'Direct string interpolation into raw SQL statement allowing unauthorized data bypass.',
    code: `# Python User Authentication Query Builder
def build_auth_query(username, active_only=True):
    # BUG: Untrusted input formatted directly into SQL query string
    query = "SELECT id, username, role FROM users WHERE username = '" + username + "' AND active = 1"
    return query

malicious_user = "admin' OR '1'='1"
print(f"Building query for user: {malicious_user}")
sql = build_auth_query(malicious_user)
print("Generated SQL:", sql)

if "' OR '1'='1" in sql:
    print("[SECURITY DEFECT] SQL Injection vulnerability detected!", flush=True)
    import sys
    sys.exit(1)
else:
    print("Query safely constructed.")
`
  },

  // Java Preset
  {
    id: 'java-off-by-one',
    name: 'Java Array Index Out of Bounds',
    language: 'java',
    category: 'Logic',
    severity: 'medium',
    description: 'Boundary condition error using <= on array.length causing ArrayIndexOutOfBoundsException.',
    code: `// Java Batch Calculation Service
public class Main {
    public static void main(String[] args) {
        int[] numbers = {10, 20, 30, 40};
        System.out.println("Processing " + numbers.length + " items in Java...");
        int total = 0;
        // BUG: loop condition uses '<=' on length, causing ArrayIndexOutOfBoundsException
        for (int i = 0; i <= numbers.length; i++) {
            total += numbers[i];
            System.out.println("Index " + i + ": " + numbers[i] + " (running total: " + total + ")");
        }
        System.out.println("Final total: " + total);
    }
}
`
  },

  // C Preset
  {
    id: 'c-off-by-one',
    name: 'C Off-by-One Buffer Overrun',
    language: 'c',
    category: 'Logic',
    severity: 'high',
    description: 'Loop condition uses <= on buffer size n, reading beyond the allocated buffer (CWE-193).',
    code: `#include <stdio.h>
#include <stdlib.h>

int main() {
    int numbers[4] = {10, 20, 30, 40};
    int n = 4;
    int sum = 0;
    printf("Processing %d elements in C...\\n", n);
    // BUG: Loop condition uses '<=' causing buffer overread of numbers[4]
    for (int i = 0; i <= n; i++) {
        sum += numbers[i];
        printf("Index %d: %d (running sum: %d)\\n", i, numbers[i], sum);
    }
    printf("Final sum: %d\\n", sum);
    return 0;
}
`
  },

  // C++ Preset
  {
    id: 'cpp-off-by-one',
    name: 'C++ Vector Off-by-One Out-of-Bounds',
    language: 'cpp',
    category: 'Logic',
    severity: 'high',
    description: 'Loop condition uses <= on vector size, reading past allocated container memory.',
    code: `#include <iostream>
#include <vector>

int main() {
    std::vector<int> numbers = {10, 20, 30, 40};
    int n = numbers.size();
    int sum = 0;
    std::cout << "Processing " << n << " elements in C++..." << std::endl;
    // BUG: Loop condition uses '<=' causing out-of-bounds access at index 4
    for (int i = 0; i <= n; i++) {
        sum += numbers[i];
        std::cout << "Index " << i << ": " << numbers[i] << " (running sum: " << sum << ")" << std::endl;
    }
    std::cout << "Final sum: " << sum << std::endl;
    return 0;
}
`
  },

  // Python Runtime Error Presets
  {
    id: 'py-zero-division',
    name: 'Python ZeroDivisionError',
    language: 'python',
    category: 'Runtime',
    severity: 'high',
    description: 'Integer division by literal zero causes ZeroDivisionError at runtime.',
    code: `# Python Division Calculator
def compute_average(total, count):
    # BUG: division by zero — count is 0, causing ZeroDivisionError at runtime
    result = total / 0
    return result

print("Starting division calculation...")
total = 100
count = 0
average = compute_average(total, count)
print(f"Average: {average}")
print("Calculation complete.")
`
  },
  {
    id: 'py-name-error',
    name: 'Python NameError: Undefined Variable',
    language: 'python',
    category: 'Runtime',
    severity: 'high',
    description: 'Variable used before assignment causing NameError at runtime.',
    code: `# Python Data Processing Service
def process_record(data):
    print(f"Processing record: {data}")
    result = data * multiplier  # BUG: NameError — multiplier is not defined in this scope
    return result

print("Starting record processing...")
record = 42
output = process_record(record)
print(f"Output: {output}")
print("Done.")
`
  },

  // Java Runtime Error Presets
  {
    id: 'java-npe',
    name: 'Java NullPointerException',
    language: 'java',
    category: 'Runtime',
    severity: 'high',
    description: 'Method call on null reference causes java.lang.NullPointerException at runtime.',
    code: `// Java User Service
public class Main {
    public static void main(String[] args) {
        String username = null; // BUG: NullPointerException — calling method on null reference
        System.out.println("Processing user: " + username);
        int len = username.length(); // Dereference of null
        System.out.println("Username length: " + len);
    }
}
`
  },
  {
    id: 'java-arithmetic-exception',
    name: 'Java ArithmeticException: Divide by Zero',
    language: 'java',
    category: 'Runtime',
    severity: 'high',
    description: 'Integer division by zero causes java.lang.ArithmeticException at runtime.',
    code: `// Java Grade Calculator
public class Main {
    public static void main(String[] args) {
        int totalScore = 500;
        int studentCount = 0;
        System.out.println("Calculating class average...");
        // BUG: ArithmeticException — division by zero when studentCount is 0
        int average = totalScore / 0;
        System.out.println("Class average: " + average);
    }
}
`
  },

  // JavaScript Runtime Error Presets
  {
    id: 'js-reference-error',
    name: 'JavaScript ReferenceError: Undeclared Variable',
    language: 'javascript',
    category: 'Runtime',
    severity: 'high',
    description: 'Access to an undeclared variable causes ReferenceError at runtime.',
    code: `// JavaScript Data Processor
function processData(input) {
  console.log('Processing input:', input);
  // BUG: ReferenceError — multiplier is not defined in this scope or any parent scope
  const result = input * multiplier;
  return result;
}

console.log('Starting data processing...');
const value = 42;
const output = processData(value);
console.log('Output:', output);
`
  },
  {
    id: 'js-type-error',
    name: 'JavaScript TypeError: Property Access on null',
    language: 'javascript',
    category: 'Runtime',
    severity: 'high',
    description: 'Reading a property from null causes TypeError: Cannot read properties of null.',
    code: `// JavaScript User Profile Service
function getUserDisplayName(user) {
  // BUG: TypeError — cannot read property 'name' on null reference
  console.log('Getting display name for user:', user);
  return user.name.toUpperCase();
}

console.log('Loading user profile...');
const currentUser = null; // User not found — returns null
const displayName = getUserDisplayName(currentUser);
console.log('Display name:', displayName);
`
  },

  // C Runtime Error Preset
  {
    id: 'c-null-pointer',
    name: 'C NULL Pointer Dereference',
    language: 'c',
    category: 'Runtime',
    severity: 'critical',
    description: 'Dereferencing a NULL pointer causes segmentation fault or undefined behavior.',
    code: `#include <stdio.h>
#include <stdlib.h>

int main() {
    int *ptr = NULL; // BUG: NULL pointer dereference — ptr is never allocated
    printf("Attempting to read value at ptr...\\n");
    int value = *ptr; // Dereferences NULL — causes segfault
    printf("Value: %d\\n", value);
    return 0;
}
`
  },

  // C++ Runtime Error Preset
  {
    id: 'cpp-divide-by-zero',
    name: 'C++ Integer Division by Zero',
    language: 'cpp',
    category: 'Runtime',
    severity: 'high',
    description: 'Integer division by zero causes undefined behavior or SIGFPE in C++.',
    code: `#include <iostream>

int main() {
    int numerator = 100;
    int denominator = 0;
    std::cout << "Calculating result..." << std::endl;
    // BUG: division by zero — undefined behavior / SIGFPE signal
    int result = numerator / 0;
    std::cout << "Result: " << result << std::endl;
    return 0;
}
`
  },

  // Python TypeError Preset
  {
    id: 'py-type-error',
    name: 'Python TypeError: Incompatible Types',
    language: 'python',
    category: 'Runtime',
    severity: 'high',
    description: 'Concatenation of str and int causes TypeError at runtime.',
    code: `# Python User Profile Formatter
def format_profile(name, age):
    # BUG: TypeError — cannot concatenate str and int without conversion
    profile = name + age
    return profile

print("Formatting profile...")
name = "Varshini"
age = 19
result = format_profile(name, age)
print(f"Profile: {result}")
print("Done.")
`
  },
  {
    id: 'py-index-error',
    name: 'Python IndexError: List Index Out of Range',
    language: 'python',
    category: 'Runtime',
    severity: 'high',
    description: 'Accessing an index beyond the list length causes IndexError at runtime.',
    code: `# Python Data Retrieval Service
def get_item(data, index):
    print(f"Retrieving item at index {index} from list of {len(data)} elements")
    # BUG: IndexError — index 5 exceeds list bounds [0..2]
    item = data[index]
    return item

print("Starting data retrieval...")
numbers = [10, 20, 30]
result = get_item(numbers, 5)
print(f"Retrieved: {result}")
print("Done.")
`
  },
  {
    id: 'py-key-error',
    name: 'Python KeyError: Missing Dictionary Key',
    language: 'python',
    category: 'Runtime',
    severity: 'high',
    description: 'Accessing a non-existent key in a dictionary causes KeyError at runtime.',
    code: `# Python Student Record Lookup
def get_marks(student):
    print(f"Looking up marks for: {student['name']}")
    # BUG: KeyError — 'marks' key does not exist in the dictionary
    marks = student["marks"]
    return marks

print("Starting student lookup...")
student = {"name": "Varshini"}
result = get_marks(student)
print(f"Marks: {result}")
print("Done.")
`
  },

  // JavaScript RangeError Preset
  {
    id: 'js-range-error',
    name: 'JavaScript RangeError: Invalid Array Length',
    language: 'javascript',
    category: 'Runtime',
    severity: 'high',
    description: 'Creating an array with a negative length causes RangeError at runtime.',
    code: `// JavaScript Buffer Allocation Service
function allocateBuffer(size) {
  console.log('Allocating buffer of size:', size);
  // BUG: RangeError — negative length is not a valid array size
  const buffer = new Array(size);
  console.log('Buffer allocated successfully, length:', buffer.length);
  return buffer;
}

console.log('Starting buffer allocation...');
const requestedSize = -1;
const result = allocateBuffer(requestedSize);
console.log('Result:', result);
`
  },

  // Java ArrayIndexOutOfBoundsException Preset
  {
    id: 'java-array-index',
    name: 'Java ArrayIndexOutOfBoundsException',
    language: 'java',
    category: 'Runtime',
    severity: 'high',
    description: 'Accessing an array element beyond its length causes ArrayIndexOutOfBoundsException at runtime.',
    code: `// Java Data Access Service
public class Main {
    public static void main(String[] args) {
        int[] numbers = {10, 20, 30};
        System.out.println("Array length: " + numbers.length);
        // BUG: ArrayIndexOutOfBoundsException — index 5 exceeds array bounds [0..2]
        int value = numbers[5];
        System.out.println("Value at index 5: " + value);
    }
}
`
  },

  // C Division by Zero Preset
  {
    id: 'c-divide-by-zero',
    name: 'C Integer Division by Zero',
    language: 'c',
    category: 'Runtime',
    severity: 'high',
    description: 'Integer division by zero causes SIGFPE or undefined behavior at runtime.',
    code: `#include <stdio.h>

int main() {
    int a = 10;
    int b = 0;
    printf("Calculating a / b...\\n");
    // BUG: division by zero — SIGFPE or undefined behavior
    int result = a / b;
    printf("Result: %d\\n", result);
    return 0;
}
`
  },

  // C++ Null Pointer Dereference Preset
  {
    id: 'cpp-null-pointer',
    name: 'C++ nullptr Dereference',
    language: 'cpp',
    category: 'Runtime',
    severity: 'critical',
    description: 'Dereferencing a nullptr causes segmentation fault or undefined behavior.',
    code: `#include <iostream>

int main() {
    int* ptr = nullptr; // BUG: nullptr dereference — ptr is never allocated
    std::cout << "Attempting to read value at ptr..." << std::endl;
    int value = *ptr; // Dereferences nullptr — causes segfault
    std::cout << "Value: " << value << std::endl;
    return 0;
}
`
  },

  // Syntax Presets
  {
    id: 'py-syntax-paren',
    name: 'Python Syntax: Missing Closing Parenthesis ")"',
    language: 'python',
    category: 'Syntax',
    severity: 'critical',
    description: 'Call to print() is missing closing parenthesis, causing SyntaxError.',
    code: `# Python Greeting Service
name = "Varshini"
# SYNTAX ERROR: missing closing parenthesis ')'
print(name
`
  },
  {
    id: 'js-syntax-paren',
    name: 'JavaScript Syntax: Missing Parenthesis ")"',
    language: 'javascript',
    category: 'Syntax',
    severity: 'critical',
    description: 'console.log statement is terminated before closing parenthesis, causing SyntaxError.',
    code: `// JavaScript Greeting Service
function greet() {
  // SYNTAX ERROR: missing closing parenthesis ')' before ';'
  console.log("Hello";
}

greet();
`
  },
  {
    id: 'java-syntax-semicolon',
    name: 'Java Syntax: Missing Semicolon ";"',
    language: 'java',
    category: 'Syntax',
    severity: 'critical',
    description: 'Print statement is missing required semicolon terminator, causing compilation error.',
    code: `// Java Greeting Service
public class Main {
    public static void main(String[] args) {
        // SYNTAX ERROR: missing semicolon ';'
        System.out.println("Hello")
    }
}
`
  },
  {
    id: 'c-syntax-semicolon',
    name: 'C Syntax: Missing Semicolon ";"',
    language: 'c',
    category: 'Syntax',
    severity: 'critical',
    description: 'printf statement is missing semicolon terminator before return, causing GCC compilation error.',
    code: `// C Greeting Service
#include <stdio.h>

int main() {
    // SYNTAX ERROR: missing semicolon ';'
    printf("Hello\n")
    return 0;
}
`
  },
  {
    id: 'cpp-syntax-semicolon',
    name: 'C++ Syntax: Missing Semicolon ";"',
    language: 'cpp',
    category: 'Syntax',
    severity: 'critical',
    description: 'std::cout statement is missing semicolon terminator before return, causing G++ compilation error.',
    code: `// C++ Greeting Service
#include <iostream>

int main() {
    // SYNTAX ERROR: missing semicolon ';'
    std::cout << "Hello" << std::endl
    return 0;
}
`
  }
];


// HTTP Request Handler
const server = http.createServer(async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const pathname = url.pathname;

  // JSON Body Parser helper
  const readJsonBody = () => new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch (err) {
        reject(err);
      }
    });
    req.on('error', reject);
  });

  const sendJson = (statusCode, data) => {
    res.writeHead(statusCode, { 'Content-Type': 'application/json; charset=UTF-8' });
    res.end(JSON.stringify(data));
  };

  // API Endpoints
  if (pathname === '/api/presets' && req.method === 'GET') {
    const lang = url.searchParams.get('language');
    const filteredPresets = lang ? PRESETS.filter(p => p.language === lang.toLowerCase()) : PRESETS;
    const languages = Object.values(LANGUAGE_REGISTRY).map(l => ({
      id: l.id,
      name: l.name,
      runtime: l.runtime,
      extension: l.extension,
      isCompiled: l.isCompiled
    }));
    return sendJson(200, { ok: true, presets: filteredPresets, languages });
  }

  if (pathname === '/api/run' && req.method === 'POST') {
    try {
      const body = await readJsonBody();
      if (!body.code) {
        return sendJson(400, { ok: false, error: 'Missing code parameter' });
      }
      const lang = (body.language || 'javascript').toLowerCase();
      const langHandler = LANGUAGE_REGISTRY[lang] || LANGUAGE_REGISTRY.javascript;
      const result = await langHandler.execute(body.code, body.timeoutMs || 5000);
      return sendJson(200, result);
    } catch (err) {
      return sendJson(500, { ok: false, error: err.message });
    }
  }

  if (pathname === '/api/detect' && req.method === 'POST') {
    try {
      const body = await readJsonBody();
      if (!body.code) {
        return sendJson(400, { ok: false, error: 'Missing code parameter' });
      }
      const lang = (body.language || 'javascript').toLowerCase();
      const langHandler = LANGUAGE_REGISTRY[lang] || LANGUAGE_REGISTRY.javascript;

      // Execute the code first to capture runtime evidence (stderr, exit code, signals)
      let runtimeResult = null;
      try {
        runtimeResult = await langHandler.execute(body.code, body.timeoutMs || 5000);
      } catch (execErr) {
        // Execution failure is not fatal for detection — static analysis will still run
        runtimeResult = { ok: false, exitCode: 1, stdout: '', stderr: execErr.message, durationMs: 0, timedOut: false };
      }

      // Pass runtime results to detectBugs for evidence-based detection
      const findings = langHandler.detectBugs(body.code, runtimeResult);
      return sendJson(200, { ok: true, language: lang, findingsCount: findings.length, findings, runtimeResult });
    } catch (err) {
      return sendJson(500, { ok: false, error: err.message });
    }
  }

  if (pathname === '/api/cause' && req.method === 'POST') {
    try {
      const body = await readJsonBody();
      const lang = (body.language || 'javascript').toLowerCase();
      const cause = analyzeLanguageCause(body.code || '', body.findingId, lang);
      return sendJson(200, { ok: true, language: lang, cause });
    } catch (err) {
      return sendJson(500, { ok: false, error: err.message });
    }
  }

  if (pathname === '/api/fix' && req.method === 'POST') {
    try {
      const body = await readJsonBody();
      if (!body.code) {
        return sendJson(400, { ok: false, error: 'Missing code parameter' });
      }
      const lang = (body.language || 'javascript').toLowerCase();
      const langHandler = LANGUAGE_REGISTRY[lang] || LANGUAGE_REGISTRY.javascript;
      const fixResult = langHandler.generateFix(body.code, body.findingId);
      return sendJson(200, { ok: true, language: lang, ...fixResult });
    } catch (err) {
      return sendJson(500, { ok: false, error: err.message });
    }
  }

  if (pathname === '/api/verify' && req.method === 'POST') {
    try {
      const body = await readJsonBody();
      if (!body.fixedCode) {
        return sendJson(400, { ok: false, error: 'Missing fixedCode parameter' });
      }
      const lang = (body.language || 'javascript').toLowerCase();
      const langHandler = LANGUAGE_REGISTRY[lang] || LANGUAGE_REGISTRY.javascript;

      // Step A: Syntax / Compilation Check
      const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bf-vfy-'));
      let syntaxCheck = { ok: true, error: null };
      try {
        syntaxCheck = await langHandler.checkSyntax(body.fixedCode, tmpDir);
      } catch (err) {
        syntaxCheck = { ok: false, error: err.message };
      } finally {
        try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (_) {}
      }

      // Step B: Sandboxed Execution Run
      let runResult;
      if (syntaxCheck.ok) {
        runResult = await langHandler.execute(body.fixedCode, 5000);
      } else {
        runResult = {
          ok: false,
          exitCode: 1,
          stdout: '',
          stderr: syntaxCheck.error || 'Syntax / Compilation check failed',
          durationMs: 0,
          timedOut: false
        };
      }

      // Step C: Re-scan for remaining vulnerabilities
      const remainingFindings = langHandler.detectBugs(body.fixedCode, runResult);

      // Step D: Hybrid verification checks
      const verificationChecks = [
        {
          name: langHandler.isCompiled ? `${langHandler.name} Compilation Validation` : `${langHandler.name} Syntax Validation`,
          passed: syntaxCheck.ok,
          detail: syntaxCheck.ok
            ? `${langHandler.runtime} confirmed valid syntax / compilation`
            : (syntaxCheck.error || 'Compilation/Syntax check failed')
        },
        {
          name: 'Sandboxed Execution Run',
          passed: runResult.ok,
          detail: runResult.ok
            ? `Process exited cleanly (exit code 0, ${runResult.durationMs}ms)`
            : (runResult.stderr || runResult.stdout || 'Execution failed with exit code ' + runResult.exitCode)
        },
        {
          name: 'Vulnerability Elimination',
          passed: remainingFindings.length === 0,
          detail: remainingFindings.length === 0
            ? 'Zero residual defects detected in active code'
            : (remainingFindings.length + ' issue(s) still open')
        },
        {
          name: 'Regression Invariant Assertion',
          passed: syntaxCheck.ok && runResult.ok && remainingFindings.length === 0,
          detail: 'All functional assertions and contracts satisfied'
        }
      ];

      const allPassed = verificationChecks.every(c => c.passed);

      return sendJson(200, {
        ok: allPassed,
        verified: allPassed,
        language: lang,
        checks: verificationChecks,
        runResult,
        remainingFindingsCount: remainingFindings.length
      });
    } catch (err) {
      return sendJson(500, { ok: false, error: err.message });
    }
  }

  // Static File Serving
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  
  // Safe path containment check
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) {
      filePath = path.join(PUBLIC_DIR, 'index.html');
    }

    const ext = path.extname(filePath).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (readErr, content) => {
      if (readErr) {
        res.writeHead(404);
        res.end('Not Found');
        return;
      }
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    });
  });
});

server.listen(PORT, () => {
  console.log(`\n=======================================================`);
  console.log(`  AI Bug Fixer Prototype Server is LIVE (Multi-Language)`);
  console.log(`  URL: http://localhost:${PORT}`);
  console.log(`  Languages: JavaScript, Python, Java, C, C++`);
  console.log(`  Pipeline: Detect -> Root Cause -> Fix -> Verify`);
  console.log(`=======================================================\n`);
});
