import { ScannedFile, SecurityFinding } from '../types';
import { CONFIG_RULES } from './rules';
import { isCommonPlaceholder } from '../utils/entropy';

export class ConfigScanner {
  public scanFiles(files: ScannedFile[]): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const file of files) {
      const fileName = file.path.split('/').pop() || file.path;
      const lowerPath = file.path.toLowerCase();
      const lines = file.content.split('\n');

      // 1. Check for committed active .env files with real credentials
      if (
        (fileName === '.env' ||
          fileName === '.env.local' ||
          fileName === '.env.production' ||
          fileName === '.env.staging') &&
        !fileName.includes('example') &&
        !fileName.includes('sample') &&
        !fileName.includes('template')
      ) {
        lines.forEach((line, idx) => {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#')) return;

          const eqIdx = trimmed.indexOf('=');
          if (eqIdx > 0) {
            const key = trimmed.slice(0, eqIdx).trim();
            const val = trimmed.slice(eqIdx + 1).trim().replace(/^["']|["']$/g, '');

            if (
              val &&
              val.length >= 4 &&
              !isCommonPlaceholder(val) &&
              (key.toLowerCase().includes('secret') ||
                key.toLowerCase().includes('key') ||
                key.toLowerCase().includes('pass') ||
                key.toLowerCase().includes('token') ||
                key.toLowerCase().includes('auth') ||
                key.toLowerCase().includes('database') ||
                key.toLowerCase().includes('db'))
            ) {
              const findingId = `cfg-committed-env-${file.path}-${idx + 1}`;
              if (!findings.some((f) => f.id === findingId)) {
                findings.push({
                  id: findingId,
                  category: 'CONFIGURATION',
                  severity: 'CRITICAL',
                  title: `Committed Environment Secret: ${key}`,
                  description: `Active configuration secret "${key}" was committed in file "${file.path}". Environment files with secrets must never be tracked in git.`,
                  impact: 'Direct exposure of database, API, and cloud authentication credentials.',
                  recommendation: 'Add .env to .gitignore, remove it from git history, and rotate all contained credentials.',
                  filePath: file.path,
                  startLine: idx + 1,
                  endLine: idx + 1,
                  cwe: 'CWE-312: Cleartext Storage of Sensitive Information',
                  confidence: 'HIGH',
                  cvssScore: 9.8,
                  snippet: `${key}=****`,
                  vulnerableSnippet: `${key}=****`,
                  fixedSnippet: `# In .env.example\n${key}=\n# Add .env to .gitignore`,
                  maskedSnippet: `${key}=****`,
                  remediationSnippet: `# In .env.example\n${key}=\n# Add .env to .gitignore`,
                });
              }
            }
          }
        });
      }

      // 2. Scan for Configuration Rules
      for (const rule of CONFIG_RULES) {
        if (rule.fileMatch && !rule.fileMatch(file.path)) {
          continue;
        }

        const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g';
        const regex = new RegExp(rule.pattern.source, flags);
        let match: RegExpExecArray | null;

        while ((match = regex.exec(file.content)) !== null) {
          const matchedText = match[0];
          const preMatch = file.content.slice(0, match.index);
          const startLine = preMatch.split('\n').length;
          const endLine = startLine;
          const lineContent = lines[startLine - 1] || matchedText;

          const findingId = `cfg-${file.path.replace(/[^a-zA-Z0-9]/g, '_')}-${startLine}-${rule.id}`;

          if (!findings.some((f) => f.id === findingId)) {
            findings.push({
              id: findingId,
              category: 'CONFIGURATION',
              severity: rule.severity,
              title: rule.name,
              description: rule.description,
              impact: rule.impact,
              recommendation: rule.recommendation,
              filePath: file.path,
              startLine,
              endLine,
              cwe: rule.cwe,
              cvssScore: rule.severity === 'CRITICAL' ? 9.8 : rule.severity === 'HIGH' ? 8.0 : 5.5,
              confidence: 'HIGH',
              snippet: lineContent.trim(),
              vulnerableSnippet: lineContent.trim(),
              fixedSnippet: rule.remediationSnippet,
              maskedSnippet: lineContent.trim(),
              remediationSnippet: rule.remediationSnippet,
            });
          }

          if (match.index === regex.lastIndex) {
            regex.lastIndex++;
          }
        }
      }
    }

    return findings;
  }
}
