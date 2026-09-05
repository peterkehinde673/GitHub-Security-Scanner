import { ScannedFile, SecurityFinding } from '../types';
import { CODE_PATTERN_RULES } from './rules';

export class CodePatternScanner {
  /**
   * Performs pattern-based SAST scanning on code files for vulnerability patterns.
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

      for (const rule of CODE_PATTERN_RULES) {
        if (rule.fileExtensions && rule.fileExtensions.length > 0) {
          const ext = '.' + file.path.split('.').pop()?.toLowerCase();
          if (!rule.fileExtensions.some((e) => e.toLowerCase() === ext)) {
            continue;
          }
        }

        const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g';
        const regex = new RegExp(rule.pattern.source, flags);
        let match: RegExpExecArray | null;
        let ruleMatches = 0;

        while ((match = regex.exec(file.content)) !== null) {
          if (rule.contextFilter && !rule.contextFilter(file.content, match)) {
            continue;
          }

          if (++ruleMatches > MAX_MATCHES_PER_RULE_PER_FILE) {
            break;
          }

          const matchedText = match[0];

          // Calculate accurate line numbers
          const preMatch = file.content.slice(0, match.index);
          const startLine = preMatch.split('\n').length;
          const matchLineCount = matchedText.split('\n').length;
          const endLine = startLine + matchLineCount - 1;
          const lineContent = lines[startLine - 1] || matchedText;

          const findingId = `pat-${file.path.replace(/[^a-zA-Z0-9]/g, '_')}-${startLine}-${rule.id}`;

          if (!seenIds.has(findingId)) {
            seenIds.add(findingId);
            findings.push({
              id: findingId,
              category: 'CODE_PATTERNS',
              severity: rule.severity,
              title: rule.name,
              description: rule.description,
              impact: rule.impact,
              recommendation: rule.recommendation,
              filePath: file.path,
              startLine,
              endLine,
              cwe: rule.cwe,
              cvssScore: rule.severity === 'CRITICAL' ? 9.8 : rule.severity === 'HIGH' ? 8.4 : 5.8,
              confidence: 'HIGH',
              snippet: lineContent.trim(),
              vulnerableSnippet: lineContent.trim(),
              fixedSnippet: rule.remediationSnippet,
              maskedSnippet: lineContent.trim(),
              remediationSnippet: rule.remediationSnippet,
            });
          }

          // Prevent infinite loop for zero-width matches
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
      lower.endsWith('.lock') ||
      lower.endsWith('-lock.json') ||
      lower.endsWith('.pdf') ||
      lower.endsWith('.svg')
    );
  }
}
