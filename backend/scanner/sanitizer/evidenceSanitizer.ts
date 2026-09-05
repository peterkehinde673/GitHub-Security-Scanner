import { SecurityFinding } from '../types';

/**
 * Secret pattern definitions for centralized evidence sanitization.
 * Applied across ALL finding categories (Secrets, SAST, Config, Dependencies).
 */
interface SecretPattern {
  name: string;
  regex: RegExp;
  mask: (match: string, ...groups: any[]) => string;
}

const SECRET_PATTERNS: SecretPattern[] = [
  // AWS Access Key ID
  {
    name: 'AWS Access Key',
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    mask: (match) => match.slice(0, 4) + '*'.repeat(match.length - 4),
  },
  // AWS Secret Access Key
  {
    name: 'AWS Secret Access Key',
    regex: /(aws_secret_access_key|aws_secret|secret_key|secretKey)\s*([:=])\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    mask: (_m, key, sep) => `${key} ${sep} "[REDACTED_AWS_SECRET]"`,
  },
  // GitHub Tokens (Personal Access Token, OAuth, etc.)
  {
    name: 'GitHub Token',
    regex: /\b(gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})\b/g,
    mask: (match) => match.slice(0, 4) + '*'.repeat(Math.min(match.length - 4, 36)),
  },
  // OpenAI API Key
  {
    name: 'OpenAI API Key',
    regex: /\b(sk-[a-zA-Z0-9T3BlbkFJ]{20,}|sk-proj-[a-zA-Z0-9_-]{20,})\b/g,
    mask: (match) => match.slice(0, 3) + '*'.repeat(Math.min(match.length - 3, 30)),
  },
  // Google Cloud / Gemini API Key
  {
    name: 'Google API Key',
    regex: /\b(AIza[0-9A-Za-z-_]{35})\b/g,
    mask: (match) => match.slice(0, 4) + '*'.repeat(match.length - 4),
  },
  // Stripe API Key (live or test)
  {
    name: 'Stripe API Key',
    regex: /\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b/g,
    mask: (match) => match.slice(0, 7) + '*'.repeat(Math.min(match.length - 7, 30)),
  },
  // Slack Webhook URL
  {
    name: 'Slack Webhook',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{8,12}\/[a-zA-Z0-9_]{24}/g,
    mask: () => 'https://hooks.slack.com/services/T********/B********/************************',
  },
  // Slack Token
  {
    name: 'Slack Token',
    regex: /\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b/g,
    mask: (match) => match.slice(0, 5) + '*'.repeat(match.length - 5),
  },
  // Private Key Blocks
  {
    name: 'Private Key',
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    mask: () => '-----BEGIN PRIVATE KEY-----\n[REDACTED_PRIVATE_KEY]\n-----END PRIVATE KEY-----',
  },
  // Bearer Token in authorization headers
  {
    name: 'Bearer Token',
    regex: /\b(Bearer\s+)([a-zA-Z0-9_\-.]{20,})\b/gi,
    mask: (_m, prefix) => `${prefix}[REDACTED_BEARER_TOKEN]`,
  },
  // Database connection string with password
  {
    name: 'DB Connection URI',
    regex: /((?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis):\/\/[^:\s]+:)([^@\s]+)(@)/gi,
    mask: (_m, prefix, _pass, suffix) => `${prefix}[REDACTED_PASSWORD]${suffix}`,
  },
  // Embedded HTTP Basic auth in URLs
  {
    name: 'Basic Auth in URL',
    regex: /(https?:\/\/[^:\s\/]+:)([^@\s\/]+)(@)/gi,
    mask: (_m, prefix, _pass, suffix) => `${prefix}[REDACTED_PASSWORD]${suffix}`,
  },
  // Generic high-entropy secret assignment: password="...", secret="...", token="..."
  {
    name: 'Generic Secret Assignment',
    regex: /\b(password|passwd|secret|api_key|apikey|access_token|auth_token|client_secret)\s*([:=])\s*(["'])([^"'\r\n]{8,})\3/gi,
    mask: (_m, key, sep, quote, val) => {
      // Do not mask obvious placeholders
      if (/^(placeholder|example|test|changeme|your[-_]?secret|none|\*+)$/i.test(val)) {
        return _m;
      }
      return `${key} ${sep} ${quote}[REDACTED_SECRET]${quote}`;
    },
  },
];

export class EvidenceSanitizer {
  /**
   * Sanitizes arbitrary text, replacing detected secrets with redacted masks while preserving surrounding context.
   */
  public static sanitizeText(text: string | undefined): string {
    if (!text || typeof text !== 'string') {
      return text || '';
    }

    let sanitized = text;
    for (const pattern of SECRET_PATTERNS) {
      sanitized = sanitized.replace(pattern.regex, pattern.mask as any);
    }
    return sanitized;
  }

  /**
   * Centralized sanitizer for all SecurityFinding objects regardless of category.
   * Guarantees that evidence fields never leak plaintext secrets.
   */
  public static sanitizeFinding(finding: SecurityFinding): SecurityFinding {
    const sanitized = { ...finding };

    if (sanitized.snippet) {
      sanitized.snippet = this.sanitizeText(sanitized.snippet);
    }
    if (sanitized.vulnerableSnippet) {
      sanitized.vulnerableSnippet = this.sanitizeText(sanitized.vulnerableSnippet);
    }
    if (sanitized.fixedSnippet) {
      sanitized.fixedSnippet = this.sanitizeText(sanitized.fixedSnippet);
    }
    if (sanitized.maskedSnippet) {
      sanitized.maskedSnippet = this.sanitizeText(sanitized.maskedSnippet);
    } else if (sanitized.snippet) {
      sanitized.maskedSnippet = sanitized.snippet;
    }
    if (sanitized.remediationSnippet) {
      sanitized.remediationSnippet = this.sanitizeText(sanitized.remediationSnippet);
    }
    if (sanitized.title) {
      sanitized.title = this.sanitizeText(sanitized.title);
    }
    if (sanitized.description) {
      sanitized.description = this.sanitizeText(sanitized.description);
    }
    if (sanitized.impact) {
      sanitized.impact = this.sanitizeText(sanitized.impact);
    }
    if (sanitized.recommendation) {
      sanitized.recommendation = this.sanitizeText(sanitized.recommendation);
    }

    return sanitized;
  }
}
