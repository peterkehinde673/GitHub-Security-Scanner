import { ScannedFile, SecurityFinding } from '../types';
import { SECRET_RULES } from './rules';
import { maskSecret, maskSnippet } from '../utils/masking';
import { calculateShannonEntropy, isCommonPlaceholder } from '../utils/entropy';

export class SecretScanner {
  /**
   * Scans an array of files for hardcoded secrets, API keys, tokens, and credentials.
   * Employs regex patterns, entropy verification, and contextual false-positive suppression.
   */
  public scanFiles(files: ScannedFile[]): SecurityFinding[] {
    const findings: SecurityFinding[] = [];
    const seenIds = new Set<string>();
    const MAX_MATCHES_PER_RULE_PER_FILE = 20;

    for (const file of files) {
      if (this.shouldSkipFile(file.path)) {
        continue;
      }

      const lines = file.content.split('\n');

      for (const rule of SECRET_RULES) {
        // Ensure global flag for iteration
        const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g';
        const regex = new RegExp(rule.pattern.source, flags);
        let match: RegExpExecArray | null;
        let ruleMatches = 0;

        while ((match = regex.exec(file.content)) !== null) {
          if (++ruleMatches > MAX_MATCHES_PER_RULE_PER_FILE) {
            break;
          }

          const matchedSecret = rule.matchIndex && match[rule.matchIndex] ? match[rule.matchIndex] : (match[1] || match[0]);

          // Filter common false positives, mock patterns, and placeholders
          if (this.isPlaceholderOrFalsePositive(matchedSecret, file.path, rule)) {
            continue;
          }

          // Optional Shannon entropy check for high-density validation
          if (rule.entropyCheck) {
            const entropy = calculateShannonEntropy(matchedSecret);
            const threshold = rule.minEntropy || 3.2;
            if (entropy < threshold) {
              continue;
            }
          }

          // Calculate exact line numbers
          const preMatch = file.content.slice(0, match.index);
          const startLine = preMatch.split('\n').length;
          const endLine = startLine;
          const lineContent = lines[startLine - 1] || match[0];

          const findingId = `sec-${file.path.replace(/[^a-zA-Z0-9]/g, '_')}-${startLine}-${rule.id}`;

          // Avoid duplicate findings
          if (!seenIds.has(findingId)) {
            seenIds.add(findingId);
            const maskedEvidence = maskSecret(matchedSecret);
            const sanitizedSnippet = maskSnippet(lineContent.trim(), matchedSecret);

            findings.push({
              id: findingId,
              category: 'SECRETS',
              severity: rule.severity,
              title: rule.name,
              description: rule.description,
              impact: 'Exposed credentials allow unauthorized attackers to access cloud infrastructure, databases, or third-party APIs with full tenant privileges.',
              recommendation: rule.recommendation,
              filePath: file.path,
              startLine,
              endLine,
              cwe: rule.cwe,
              cvssScore: rule.severity === 'CRITICAL' ? 9.8 : rule.severity === 'HIGH' ? 8.2 : 5.5,
              confidence: 'HIGH',
              snippet: sanitizedSnippet,
              vulnerableSnippet: sanitizedSnippet,
              fixedSnippet: `// Remediation: Load from secure environment variable\nconst secretKey = process.env.SECRET_KEY || '';`,
              maskedSnippet: maskedEvidence,
              remediationSnippet: `// Remediation: Load from secure environment variable\nconst secretKey = process.env.SECRET_KEY || '';`,
            });
          }

          // Advance regex index for zero-length match safety
          if (match.index === regex.lastIndex) {
            regex.lastIndex++;
          }
        }
      }
    }

    return findings;
  }

  private shouldSkipFile(filePath: string): boolean {
    const lower = filePath.toLowerCase();
    return (
      lower.endsWith('.png') ||
      lower.endsWith('.jpg') ||
      lower.endsWith('.jpeg') ||
      lower.endsWith('.gif') ||
      lower.endsWith('.svg') ||
      lower.endsWith('.ico') ||
      lower.endsWith('.woff') ||
      lower.endsWith('.woff2') ||
      lower.endsWith('.ttf') ||
      lower.endsWith('.pdf') ||
      lower.endsWith('.zip') ||
      lower.endsWith('.tar.gz') ||
      lower.endsWith('.lock') ||
      lower.endsWith('-lock.json') ||
      lower.endsWith('.min.js') ||
      lower.endsWith('.min.css') ||
      lower.endsWith('.map')
    );
  }

  private isPlaceholderOrFalsePositive(text: string, filePath: string, rule: any): boolean {
    if (!text) return true;

    // Check generic placeholder list
    if (isCommonPlaceholder(text)) {
      return true;
    }

    const lower = text.toLowerCase();
    const isDoc = filePath.toLowerCase().endsWith('.md') || filePath.toLowerCase().includes('doc') || filePath.toLowerCase().includes('test');

    // Filter documentation placeholders
    if (isDoc && (lower.includes('your_') || lower.includes('dummy') || lower.includes('example') || lower.includes('sample'))) {
      return true;
    }

    // AWS AKID special false positive checks: Must not be all same character or sequential alphabet
    if (rule.id === 'sec-aws-akid') {
      const idPart = text.slice(4);
      if (/^[A-Z0-9]{16}$/.test(idPart)) {
        // If it's pure alphabetical sequential like ABCDEFGHIJKLMNOP, skip
        if (idPart === 'ABCDEFGHIJKLMNOP' || idPart === '0123456789ABCDEF') return true;
      }
    }

    return false;
  }
}
