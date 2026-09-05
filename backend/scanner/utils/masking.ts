/**
 * Redact sensitive secrets in finding outputs and snippets.
 * Ensures the actual secret is NEVER included in API responses, logs, or reports.
 */
export function maskSecret(secret: string): string {
  if (!secret) return '[REDACTED]';
  const clean = secret.trim();
  const len = clean.length;

  if (len <= 8) {
    return '[REDACTED]';
  }

  // Preserve standard token identifiers for recognizability while masking the value
  if (clean.startsWith('ghp_')) {
    return `ghp_${'*'.repeat(12)}...${clean.slice(-4)}`;
  }
  if (clean.startsWith('github_pat_')) {
    return `github_pat_${'*'.repeat(12)}...${clean.slice(-4)}`;
  }
  if (clean.startsWith('sk_live_')) {
    return `sk_live_${'*'.repeat(12)}...${clean.slice(-4)}`;
  }
  if (clean.startsWith('sk-proj-') || clean.startsWith('sk-')) {
    return `sk-${'*'.repeat(12)}...${clean.slice(-4)}`;
  }
  if (clean.startsWith('AKIA') || clean.startsWith('ASIA') || clean.startsWith('AROA')) {
    return `${clean.slice(0, 4)}${'*'.repeat(8)}...${clean.slice(-3)}`;
  }
  if (clean.startsWith('AIza')) {
    return `AIza${'*'.repeat(12)}...${clean.slice(-3)}`;
  }
  if (clean.startsWith('xox')) {
    const prefix = clean.split('-')[0] || 'xox';
    return `${prefix}-${'*'.repeat(8)}...${clean.slice(-4)}`;
  }

  // Default redaction: 3 leading chars, 3 trailing chars, masked center
  const prefix = clean.slice(0, Math.min(3, Math.floor(len / 4)));
  const suffix = clean.slice(-Math.min(3, Math.floor(len / 4)));
  return `${prefix}${'*'.repeat(8)}...${suffix}`;
}

/**
 * Sanitizes code snippets by replacing any occurrence of the detected secret with its masked representation.
 */
export function maskSnippet(snippet: string, secret: string): string {
  if (!snippet) return '';
  if (!secret) return snippet;

  const masked = maskSecret(secret);
  // Global replacement of the raw secret
  return snippet.split(secret).join(masked);
}

/**
 * Sanitizes arbitrary text to strip obvious raw credentials.
 */
export function sanitizeEvidence(text: string): string {
  if (!text) return '';
  return text
    .replace(/\b(AKIA[A-Z0-9]{16})\b/g, (m) => maskSecret(m))
    .replace(/\b(ghp_[A-Za-z0-9_]{36,40})\b/g, (m) => maskSecret(m))
    .replace(/\b(sk_live_[0-9a-zA-Z]{24,99})\b/g, (m) => maskSecret(m))
    .replace(/\b(AIza[0-9A-Za-z-_]{35})\b/g, (m) => maskSecret(m));
}
