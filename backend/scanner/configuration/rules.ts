import { Severity } from '../types';

export interface ConfigRule {
  id: string;
  name: string;
  category: 'CONFIGURATION';
  cwe: string;
  severity: Severity;
  pattern: RegExp;
  description: string;
  impact: string;
  recommendation: string;
  remediationSnippet?: string;
  fileMatch?: (path: string) => boolean;
}

export const CONFIG_RULES: ConfigRule[] = [
  // 1. Dockerfile: Container Runs as Root
  {
    id: 'cfg-docker-root',
    name: 'Dockerfile: Container Runs as Root User',
    category: 'CONFIGURATION',
    cwe: 'CWE-250: Execution with Unnecessary Privileges',
    severity: 'MEDIUM',
    pattern: /USER\s+root/i,
    description: 'Explicitly executing container processes as root increases the blast radius if container escape or RCE vulnerabilities occur.',
    impact: 'Full host root privilege escalation in case of container isolation bypass.',
    recommendation: 'Create a non-root group and user (e.g. `USER node` or `USER appuser`) before runtime execution.',
    remediationSnippet: `RUN addgroup -S appgroup && adduser -S appuser -G appgroup\nUSER appuser`,
    fileMatch: (p) => p.toLowerCase().includes('dockerfile'),
  },
  // 2. Untrusted Remote Script Pipe to Shell
  {
    id: 'cfg-curl-pipe-sh',
    name: 'Untrusted Remote Script Pipe to Shell',
    category: 'CONFIGURATION',
    cwe: 'CWE-494: Download of Code Without Integrity Check',
    severity: 'HIGH',
    pattern: /(?:curl|wget)\s+[^|\n]+\|\s*(?:bash|sh|zsh)/i,
    description: 'Downloading shell scripts from the Internet and immediately executing them via pipe (| bash) without hash verification poses supply chain compromise risk.',
    impact: 'Man-in-the-middle code execution and untrusted remote code delivery.',
    recommendation: 'Download script to disk, verify SHA256 checksum, and inspect before running.',
    remediationSnippet: `curl -fsSL https://vendor.com/install.sh -o install.sh\necho "<checksum>  install.sh" | sha256sum -c -\nbash install.sh`,
  },
  // 3. Debug Mode Enabled in Production
  {
    id: 'cfg-debug-enabled',
    name: 'Production Debug Mode Enabled',
    category: 'CONFIGURATION',
    cwe: 'CWE-489: Active Debug Code in Production',
    severity: 'HIGH',
    pattern: /(?:app\.config\['DEBUG'\]\s*=\s*True|debug\s*=\s*True|DEBUG\s*=\s*True|debug:\s*true)/i,
    description: 'Debug mode exposes interactive debuggers (such as Werkzeug console) that can be exploited for arbitrary Python code execution.',
    impact: 'Interactive Python pin console arbitrary execution and internal stack trace leak.',
    recommendation: 'Disable debug mode in production or load from environment variables (e.g., `DEBUG = os.getenv("DEBUG", "False") == "True"`).',
    remediationSnippet: `DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'`,
  },
  // 4. Wildcard CORS Policy
  {
    id: 'cfg-wildcard-cors',
    name: 'Permissive Wildcard CORS Policy (Access-Control-Allow-Origin: *)',
    category: 'CONFIGURATION',
    cwe: 'CWE-942: Permissive Cross-domain Policy',
    severity: 'MEDIUM',
    pattern: /(?:cors\(\s*\{\s*origin:\s*['"]\*['"]|res\.setHeader\(['"]Access-Control-Allow-Origin['"],\s*['"]\*['"]\))/i,
    description: 'Allowing all origins (*) to access sensitive authenticated API routes can allow cross-site data exfiltration.',
    impact: 'Cross-origin extraction of confidential user API responses.',
    recommendation: 'Specify explicit trusted origins in CORS configuration.',
    remediationSnippet: `app.use(cors({ origin: ['https://app.yourdomain.com'], credentials: true }));`,
  },
  // 5. Insecure Cookie Settings (Missing HttpOnly / Secure)
  {
    id: 'cfg-insecure-cookie',
    name: 'Insecure Cookie Configuration (httpOnly: false or secure: false)',
    category: 'CONFIGURATION',
    cwe: 'CWE-614: Sensitive Cookie in HTTPS Session Without "Secure" Attribute',
    severity: 'MEDIUM',
    pattern: /(?:httpOnly\s*:\s*false|secure\s*:\s*false)/i,
    description: 'Cookies configured without httpOnly or secure flags can be accessed by client-side scripts (DOM XSS) or intercepted over unencrypted HTTP.',
    impact: 'Session token theft and unauthorized session takeover.',
    recommendation: 'Set httpOnly: true and secure: true on all session cookies in production.',
    remediationSnippet: `res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' });`,
  },
  // 6. Disabled Authentication / Authorization
  {
    id: 'cfg-disabled-auth',
    name: 'Disabled Authentication or Security Bypass Configuration',
    category: 'CONFIGURATION',
    cwe: 'CWE-306: Missing Authentication for Critical Function',
    severity: 'HIGH',
    pattern: /(?:allowAnonymous\s*:\s*true|skipAuth\s*:\s*true|auth\s*:\s*false|security:\s*\[\s*\])/i,
    description: 'Explicit configuration directive disabling authentication or permitting anonymous access to protected routes.',
    impact: 'Unauthenticated access to internal API endpoints and customer data.',
    recommendation: 'Ensure all non-public routes enforce authentication middleware.',
    remediationSnippet: `app.use('/api/protected', requireAuth);`,
  },
  // 7. Overly Permissive GitHub Actions Permissions
  {
    id: 'cfg-github-actions-permissions',
    name: 'Overly Permissive GitHub Actions Workflow Permissions (write-all)',
    category: 'CONFIGURATION',
    cwe: 'CWE-250: Execution with Unnecessary Privileges',
    severity: 'HIGH',
    pattern: /permissions:\s*write-all/i,
    description: 'Granting write-all permissions to GitHub GITHUB_TOKEN gives the workflow full write access to repository contents, packages, issues, and deployments.',
    impact: 'Workflows compromised by pull requests or dependencies can tamper with repository code and release assets.',
    recommendation: 'Follow principle of least privilege and grant only required specific permissions (e.g. `contents: read`).',
    remediationSnippet: `permissions:\n  contents: read\n  pull-requests: write`,
    fileMatch: (p) => p.toLowerCase().includes('.github/workflows') || p.toLowerCase().endsWith('.yml') || p.toLowerCase().endsWith('.yaml'),
  },
  // 8. Exposed NPM Auth Token in .npmrc
  {
    id: 'cfg-npmrc-token',
    name: 'Exposed NPM Auth Token in .npmrc',
    category: 'CONFIGURATION',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    severity: 'CRITICAL',
    pattern: /_authToken\s*=\s*([a-zA-Z0-9_-]{20,})/i,
    description: 'Plaintext NPM authentication token found committed inside .npmrc file.',
    impact: 'NPM package hijack, malicious version publishing, and organization supply-chain attack.',
    recommendation: 'Use environment variables in .npmrc (e.g. `//registry.npmjs.org/:_authToken=\${NPM_TOKEN}`).',
    remediationSnippet: `//registry.npmjs.org/:_authToken=\${NPM_TOKEN}`,
  },
];
