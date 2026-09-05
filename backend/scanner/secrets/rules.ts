export interface SecretRule {
  id: string;
  name: string;
  pattern: RegExp;
  cwe: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  description: string;
  recommendation: string;
  matchIndex?: number;
  entropyCheck?: boolean;
  minEntropy?: number;
}

export const SECRET_RULES: SecretRule[] = [
  // 1. AWS Access Key ID
  {
    id: 'sec-aws-akid',
    name: 'AWS Access Key ID Detected',
    pattern: /\b((?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})\b/g,
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    severity: 'CRITICAL',
    description: 'An active AWS Access Key ID was detected hardcoded in source code.',
    recommendation: 'Revoke and rotate this key immediately in AWS IAM. Store keys exclusively in environment variables (AWS_ACCESS_KEY_ID) or use AWS IAM Roles/Instance Profiles.',
  },
  // 2. AWS Secret Access Key
  {
    id: 'sec-aws-secret',
    name: 'AWS Secret Access Key Detected',
    pattern: /(?:aws_secret_access_key|aws_sec_key|aws_secret|secret_key|awsSecretAccessKey)\s*[:=]\s*["']([A-Za-z0-9\/+=]{40})["']/gi,
    matchIndex: 1,
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    severity: 'CRITICAL',
    description: 'An AWS Secret Access Key was detected in plain text.',
    recommendation: 'Rotate the secret key immediately via AWS IAM and inject credentials using IAM roles or secret managers.',
    entropyCheck: true,
    minEntropy: 3.5,
  },
  // 3. GitHub Tokens (Classic, Fine-grained, OAuth, App tokens)
  {
    id: 'sec-github-pat',
    name: 'GitHub Personal Access Token Detected',
    pattern: /\b(gh[pousr]_[A-Za-z0-9_]{36,40}|github_pat_[A-Za-z0-9_]{60,95})\b/g,
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    severity: 'CRITICAL',
    description: 'GitHub personal access token, user token, or fine-grained token exposed in repository.',
    recommendation: 'Revoke this token immediately on GitHub Settings -> Developer Settings -> Personal access tokens. Use GitHub Actions secrets or App installation tokens.',
  },
  // 4. OpenAI API Keys (Legacy and Project-scoped)
  {
    id: 'sec-openai-key',
    name: 'OpenAI API Key Detected',
    pattern: /\b(sk-(?:proj-)?[A-Za-z0-9_-]{32,80})\b/g,
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    severity: 'CRITICAL',
    description: 'OpenAI API Secret Key detected. Exposed keys allow unauthorized LLM usage, billing exhaustion, and prompt extraction.',
    recommendation: 'Revoke the compromised key from the OpenAI Platform dashboard and load keys exclusively via OPENAI_API_KEY environment variable.',
    entropyCheck: true,
    minEntropy: 3.8,
  },
  // 5. Stripe Secret / Restricted API Keys
  {
    id: 'sec-stripe-key',
    name: 'Stripe Secret / Restricted API Key Detected',
    pattern: /\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b/g,
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    severity: 'CRITICAL',
    description: 'Stripe secret or restricted API key identified in code, risking financial transaction manipulation.',
    recommendation: 'Roll the key in Stripe Dashboard -> Developers -> API keys. Move keys to secure backend environment variables.',
  },
  // 6. Google API Key (GCP / Maps / Firebase Web)
  {
    id: 'sec-google-api-key',
    name: 'Google Cloud / Maps API Key Detected',
    pattern: /\b(AIza[0-9A-Za-z-_]{35})\b/g,
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    severity: 'HIGH',
    description: 'Google Cloud API key detected. If unrestricted, an attacker can consume billable GCP APIs.',
    recommendation: 'Restrict the API key by HTTP referrers, IP addresses, or specific API scopes in Google Cloud Console. Rotate and load from environment variables.',
  },
  // 7. Slack Tokens (Bot, User, App)
  {
    id: 'sec-slack-token',
    name: 'Slack Bot / User / App Token Detected',
    pattern: /\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,36}|xapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[a-f0-9]+)\b/g,
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    severity: 'HIGH',
    description: 'Slack OAuth access token or App-level token exposed in source code.',
    recommendation: 'Revoke the token in Slack API portal and load via SLACK_BOT_TOKEN environment variable.',
  },
  // 8. Cryptographic Private Keys
  {
    id: 'sec-private-key',
    name: 'Asymmetric Private Key (RSA / EC / OpenSSH / PGP) Detected',
    pattern: /(-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----)/g,
    cwe: 'CWE-312: Cleartext Storage of Sensitive Information',
    severity: 'CRITICAL',
    description: 'Unencrypted cryptographic private key file or string committed to repository.',
    recommendation: 'Remove private keys from repository history. Generate new cryptographic keypairs and manage private keys in KMS or secure hardware/secrets manager.',
  },
  // 9. Hardcoded JWT Secret / Signing Key
  {
    id: 'sec-jwt-secret',
    name: 'Hardcoded JWT Secret / Signing Key',
    pattern: /(?:jwt[_-]?secret|token[_-]?secret|jwt[_-]?key|jwtSecret)\s*[:=]\s*["']([^"'\s]{8,})["']/gi,
    matchIndex: 1,
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    severity: 'HIGH',
    description: 'Hardcoded secret used for signing or verifying JSON Web Tokens.',
    recommendation: 'Use high-entropy randomly generated secrets loaded exclusively from runtime environment variables.',
    entropyCheck: true,
    minEntropy: 3.0,
  },
  // 10. Database Connection String with Embedded Credentials
  {
    id: 'sec-db-uri-credentials',
    name: 'Database Connection String with Embedded Credentials',
    pattern: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[a-zA-Z0-9_.-]+:([^@\s]{3,})@[a-zA-Z0-9_.-]+/gi,
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    severity: 'CRITICAL',
    description: 'Database connection URI contains hardcoded username and password.',
    recommendation: 'Store database credentials in environment variables (e.g. DATABASE_URL) and do not commit connection strings with embedded passwords.',
  },
  // 11. Generic API Key / Secret assignments
  {
    id: 'sec-generic-api-key',
    name: 'Generic API Key / Secret Token Assignment',
    pattern: /(?:api[_-]?key|apikey|api_secret|access_token|client_secret)\s*[:=]\s*["']([A-Za-z0-9_\-\.]{20,64})["']/gi,
    matchIndex: 1,
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    severity: 'HIGH',
    description: 'Plaintext high-entropy API key or client secret assigned in source code.',
    recommendation: 'Move credentials to a .env file or cloud secrets manager. Never commit production credentials into source control.',
    entropyCheck: true,
    minEntropy: 3.8,
  },
  // 12. Generic Bearer Token
  {
    id: 'sec-generic-bearer-token',
    name: 'Hardcoded Bearer Authentication Token',
    pattern: /['"]Bearer\s+([A-Za-z0-9_\-\.]{25,128})['"]/gi,
    matchIndex: 1,
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    severity: 'HIGH',
    description: 'Hardcoded authorization Bearer token identified in header configuration or HTTP client call.',
    recommendation: 'Retrieve Bearer tokens dynamically through OAuth flows or environment variables.',
    entropyCheck: true,
    minEntropy: 3.6,
  },
  // 13. Azure Storage / Cloud Connection Strings
  {
    id: 'sec-azure-conn-string',
    name: 'Azure Storage Account Key / Connection String',
    pattern: /(?:DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9\/+=]{64,88})/gi,
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    severity: 'CRITICAL',
    description: 'Azure Storage Account connection string with AccountKey detected in plaintext.',
    recommendation: 'Use Azure Managed Identities or Azure Key Vault references instead of embedding AccountKeys in code.',
  },
];
