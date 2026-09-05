import { Severity } from '../types';

export interface CodePatternRule {
  id: string;
  name: string;
  category: 'CODE_PATTERNS';
  cwe: string;
  severity: Severity;
  pattern: RegExp;
  description: string;
  impact: string;
  recommendation: string;
  remediationSnippet?: string;
  fileExtensions?: string[];
  contextFilter?: (content: string, match: RegExpExecArray) => boolean;
}

export const CODE_PATTERN_RULES: CodePatternRule[] = [
  // 1. SQL Injection via String Concatenation or Interpolation (JS/TS, Python, PHP, Java)
  {
    id: 'pat-sqli-concat',
    name: 'SQL Injection via String Concatenation or Dynamic Interpolation',
    category: 'CODE_PATTERNS',
    cwe: 'CWE-89: SQL Injection',
    severity: 'CRITICAL',
    pattern: /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*?\+.*?['"][^'"]*['"]|\b(?:query|raw|execute)\s*\(\s*["'`].*?\$\{.*?\}/i,
    description: 'Dynamic construction of SQL queries using unsanitized user input allows attackers to execute arbitrary SQL commands, bypass authentication, and exfiltrate database records.',
    impact: 'Full database compromise, unauthorized data modification or total data extraction.',
    recommendation: 'Use parameterized queries, prepared statements, or an ORM with placeholder bindings.',
    remediationSnippet: `// Secure Parameterized Query\nconst result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);`,
  },
  // 2. Python SQL Injection
  {
    id: 'pat-py-sqli-fstring',
    name: 'Python SQL Injection via f-string or string formatting',
    category: 'CODE_PATTERNS',
    cwe: 'CWE-89: SQL Injection',
    severity: 'CRITICAL',
    pattern: /(?:cursor|db|session)\.execute\s*\(\s*(?:f["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*\{|["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE)[^"']*%\s*\()/i,
    description: 'Executing dynamic SQL constructed via Python f-strings or %-formatting bypasses database parameter escaping.',
    impact: 'Direct database exfiltration or privilege escalation.',
    recommendation: 'Pass query parameters as a separate tuple or dictionary: cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
    remediationSnippet: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
  },
  // 3. Command Injection (Remote Code Execution in Node/Python/PHP/Java/Go/Ruby)
  {
    id: 'pat-cmd-injection',
    name: 'Command Injection (Remote Code Execution)',
    category: 'CODE_PATTERNS',
    cwe: 'CWE-78: OS Command Injection',
    severity: 'CRITICAL',
    pattern: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}|[^)]*\+)|(?:os\.system|os\.popen|subprocess\.(?:Popen|call|check_output|run))\s*\([^)]*(?:\+|shell\s*=\s*True)/i,
    description: 'Passing untrusted input directly to operating system shell commands allows attackers to execute arbitrary system binaries and compromise the host container.',
    impact: 'Complete server takeover, lateral movement, and host filesystem manipulation.',
    recommendation: 'Avoid spawning system shells. Pass arguments as separate array elements with shell=false and validate against an allowlist.',
    remediationSnippet: `// Secure Spawn without shell\nconst { spawn } = require('child_process');\nspawn('ping', ['-c', '1', targetHost]);`,
  },
  // 4. Insecure eval() and new Function() (JS/TS, Python, PHP, Ruby)
  {
    id: 'pat-code-eval',
    name: 'Dynamic Code Execution via eval() / new Function()',
    category: 'CODE_PATTERNS',
    cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
    severity: 'CRITICAL',
    pattern: /\b(?:eval\s*\(|new\s+Function\s*\([^)]*['"`]\))/i,
    description: 'Executing strings as code at runtime allows attackers to execute arbitrary scripts and gain full control over the runtime environment.',
    impact: 'Arbitrary code execution within the process execution context.',
    recommendation: 'Refactor code to use structured data parsers (e.g. JSON.parse) or safe lookup tables instead of dynamic evaluation.',
    remediationSnippet: `// Replace eval with safe JSON parsing\nconst data = JSON.parse(jsonString);`,
  },
  // 5. Cross-Site Scripting (XSS) via dangerouslySetInnerHTML
  {
    id: 'pat-xss-dangerouslySet',
    name: 'Cross-Site Scripting (XSS) via dangerouslySetInnerHTML',
    category: 'CODE_PATTERNS',
    cwe: 'CWE-79: Cross-site Scripting',
    severity: 'HIGH',
    pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:\s*[^}]+\}\s*\}/i,
    description: 'Directly injecting unescaped user-controlled HTML into the React DOM allows client-side script execution, session token theft, and DOM defacement.',
    impact: 'User account hijacking, session cookie exfiltration, and malicious redirect attacks.',
    recommendation: 'Render text natively in JSX elements or sanitize HTML strings using DOMPurify before rendering.',
    remediationSnippet: `import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userContent) }} />`,
  },
  // 6. Insecure Deserialization via Python Pickle
  {
    id: 'pat-python-pickle',
    name: 'Insecure Deserialization via Python Pickle',
    category: 'CODE_PATTERNS',
    cwe: 'CWE-502: Deserialization of Untrusted Data',
    severity: 'CRITICAL',
    pattern: /pickle\.(?:loads|load)\s*\(/i,
    description: 'Deserializing untrusted pickle payloads allows arbitrary Python code execution during bytecode reduction.',
    impact: 'Remote code execution in the context of the running application service.',
    recommendation: 'Never deserialize untrusted data with pickle. Use safe serialization standards such as JSON, Protocol Buffers, or MessagePack.',
    remediationSnippet: `import json\ndata = json.loads(payload_bytes.decode('utf-8'))`,
  },
  // 7. Insecure YAML Load (PyYAML unsafe loading)
  {
    id: 'pat-python-yaml-unsafe',
    name: 'Insecure YAML Deserialization (yaml.load without SafeLoader)',
    category: 'CODE_PATTERNS',
    cwe: 'CWE-502: Deserialization of Untrusted Data',
    severity: 'CRITICAL',
    pattern: /yaml\.load\s*\([^)]*(?<!Loader=yaml\.SafeLoader|Loader=SafeLoader)\)/i,
    description: 'Calling yaml.load() without SafeLoader allows arbitrary Python object instantiation and code execution.',
    impact: 'Arbitrary remote code execution.',
    recommendation: 'Use yaml.safe_load(data) instead of yaml.load(data).',
    remediationSnippet: `import yaml\ndata = yaml.safe_load(yaml_content)`,
  },
  // 8. PHP Dangerous Execution Functions
  {
    id: 'pat-php-dangerous-exec',
    name: 'PHP Dangerous Shell Execution / Include Vulnerability',
    category: 'CODE_PATTERNS',
    cwe: 'CWE-78: OS Command Injection',
    severity: 'CRITICAL',
    pattern: /\b(?:shell_exec|passthru|system|proc_open)\s*\(|\b(?:include|require|include_once|require_once)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)/i,
    description: 'PHP execution functions or dynamic file inclusions using request variables allow Remote File Inclusion (RFI) or OS command execution.',
    impact: 'Arbitrary PHP script or command execution on the server.',
    recommendation: 'Disable dangerous execution functions in php.ini and strictly whitelist static file inclusions.',
    remediationSnippet: `// Use static whitelist mapping\n$allowedPages = ['home' => 'home.php', 'about' => 'about.php'];\n$page = $allowedPages[$_GET['page']] ?? 'home.php';\ninclude($page);`,
  },
  // 9. Path Traversal / Arbitrary File Access
  {
    id: 'pat-path-traversal',
    name: 'Path Traversal / Arbitrary File Access',
    category: 'CODE_PATTERNS',
    cwe: 'CWE-22: Path Traversal',
    severity: 'HIGH',
    pattern: /(?:fs\.readFile|fs\.readFileSync|open)\s*\([^)]*(?:\+|\$\{).*?(?:req\.|query|params|filename|path)/i,
    description: 'Constructing filesystem paths with unsanitized parameters allows directory traversal sequences (../) to read arbitrary system files (e.g., /etc/passwd).',
    impact: 'Disclosure of sensitive configuration files, source code, and credentials.',
    recommendation: 'Resolve paths against a canonical base directory and ensure the target starts with the base path, or validate against an allowed filename whitelist.',
    remediationSnippet: `const safePath = path.join(BASE_DIR, path.basename(userFilename));\nif (!safePath.startsWith(BASE_DIR)) throw new Error('Access denied');`,
  },
  // 10. Disabled TLS / SSL Certificate Verification
  {
    id: 'pat-disabled-tls',
    name: 'Disabled TLS / SSL Certificate Verification',
    category: 'CODE_PATTERNS',
    cwe: 'CWE-295: Improper Certificate Validation',
    severity: 'CRITICAL',
    pattern: /(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?|verify\s*=\s*False|CURLOPT_SSL_VERIFYPEER\s*,\s*0|InsecureSkipVerify\s*:\s*true)/i,
    description: 'Disabling SSL/TLS certificate verification allows Man-In-The-Middle (MITM) attackers to intercept, decrypt, and alter network traffic.',
    impact: 'Eavesdropping on API requests, credentials, and encrypted communications.',
    recommendation: 'Always enforce valid TLS certificate verification in production environments.',
    remediationSnippet: `const agent = new https.Agent({ rejectUnauthorized: true });`,
  },
  // 11. Insecure Random Number Generation for Security-Sensitive Tasks
  {
    id: 'pat-insecure-randomness',
    name: 'Cryptographically Insecure Random Generation in Security Context',
    category: 'CODE_PATTERNS',
    cwe: 'CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator',
    severity: 'MEDIUM',
    pattern: /(?:token|secret|password|key|nonce|salt|sessionId)\s*[:=][^;\n]*(?:Math\.random\(\)|random\.(?:randint|random|choice)\()/i,
    description: 'Math.random() and standard Python random are pseudo-random generators with predictable seeds and should not be used to generate security tokens or passwords.',
    impact: 'Token prediction, session hijacking, and brute-force vulnerability.',
    recommendation: 'Use cryptographic random generators: crypto.randomBytes() in Node.js or secrets module in Python.',
    remediationSnippet: `import crypto from 'crypto';\nconst token = crypto.randomBytes(32).toString('hex');`,
  },
  // 12. Weak Hashing Algorithm (MD5 / SHA1)
  {
    id: 'pat-weak-crypto-md5',
    name: 'Use of Cryptographically Weak Hash Algorithm (MD5/SHA1)',
    category: 'CODE_PATTERNS',
    cwe: 'CWE-328: Use of Weak Cryptographic Hash',
    severity: 'MEDIUM',
    pattern: /crypto\.createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|hashlib\.(?:md5|sha1)\s*\(/i,
    description: 'MD5 and SHA-1 are vulnerable to collision attacks and rainbow table lookups and should not be used for security-sensitive operations or password hashing.',
    impact: 'Password cracking and cryptographic signature forgery.',
    recommendation: 'Use Argon2, bcrypt, or PBKDF2 for password hashing, and SHA-256 / SHA-3 for integrity digests.',
    remediationSnippet: `import bcrypt from 'bcrypt';\nconst hash = await bcrypt.hash(password, 12);`,
  },
];
