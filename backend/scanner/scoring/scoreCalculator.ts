import { SecurityFinding, SecurityScoreMetrics } from '../types';

export class ScoreCalculator {
  public static calculate(
    findings: SecurityFinding[],
    filesAnalyzed: number,
    linesAnalyzed: number,
    scanDurationMs: number
  ): SecurityScoreMetrics {
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let informationalCount = 0;

    let secretsCount = 0;
    let codePatternsCount = 0;
    let dependenciesCount = 0;
    let configurationCount = 0;

    const deductions: { category: string; points: number; reason: string }[] = [];

    for (const f of findings) {
      if (f.category === 'SECRETS' || f.category === 'SECRETS_LEAK') secretsCount++;
      else if (f.category === 'CODE_PATTERNS' || f.category === 'INJECTION' || f.category === 'XSS') codePatternsCount++;
      else if (f.category === 'DEPENDENCIES' || f.category === 'DEPENDENCY_VULN') dependenciesCount++;
      else configurationCount++;

      switch (f.severity) {
        case 'CRITICAL':
          criticalCount++;
          deductions.push({
            category: f.category,
            points: 25,
            reason: `[CRITICAL] ${f.title} in ${f.filePath}:${f.startLine}`,
          });
          break;
        case 'HIGH':
          highCount++;
          deductions.push({
            category: f.category,
            points: 15,
            reason: `[HIGH] ${f.title} in ${f.filePath}:${f.startLine}`,
          });
          break;
        case 'MEDIUM':
          mediumCount++;
          deductions.push({
            category: f.category,
            points: 8,
            reason: `[MEDIUM] ${f.title} in ${f.filePath}:${f.startLine}`,
          });
          break;
        case 'LOW':
          lowCount++;
          deductions.push({
            category: f.category,
            points: 3,
            reason: `[LOW] ${f.title} in ${f.filePath}:${f.startLine}`,
          });
          break;
        default:
          informationalCount++;
      }
    }

    const totalDeductions = deductions.reduce((sum, d) => sum + d.points, 0);
    const score = Math.max(0, Math.min(100, Math.round(100 - totalDeductions)));

    let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' = 'A+';
    if (score < 45) grade = 'F';
    else if (score < 60) grade = 'D';
    else if (score < 75) grade = 'C';
    else if (score < 88) grade = 'B';
    else if (score < 96) grade = 'A';

    let verdict: 'EXCELLENT' | 'VERY_GOOD' | 'NEEDS_ATTENTION' | 'RISKY' | 'CRITICAL_RISK' = 'EXCELLENT';
    if (criticalCount > 0 || score < 50) {
      verdict = 'CRITICAL_RISK';
    } else if (highCount > 0 || score < 70) {
      verdict = 'RISKY';
    } else if (mediumCount > 0 || score < 85) {
      verdict = 'NEEDS_ATTENTION';
    } else if (score < 95) {
      verdict = 'VERY_GOOD';
    }

    return {
      score,
      grade,
      verdict,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount: informationalCount,
      informationalCount,
      totalIssues: findings.length,
      totalFindings: findings.length,
      categoryBreakdown: {
        secrets: secretsCount,
        codePatterns: codePatternsCount,
        dependencies: dependenciesCount,
        configuration: configurationCount,
      },
      scoreDeductions: deductions,
      filesAnalyzed,
      linesAnalyzed,
      scanDurationMs,
    };
  }
}
