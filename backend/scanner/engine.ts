import { ScannedFile, ScanResult, SecurityFinding, ScanCoverage } from './types';
import { SecretScanner } from './secrets/secretScanner';
import { CodePatternScanner } from './code-patterns/patternScanner';
import { DependencyScanner } from './dependencies/dependencyScanner';
import { ConfigScanner } from './configuration/configScanner';
import { ScoreCalculator } from './scoring/scoreCalculator';
import { FileFilter } from './filesystem/fileFilter';
import { EvidenceSanitizer } from './sanitizer/evidenceSanitizer';

export const MAX_TOTAL_FINDINGS = 500;

export class SecurityScanEngine {
  private secretScanner = new SecretScanner();
  private patternScanner = new CodePatternScanner();
  private dependencyScanner = new DependencyScanner();
  private configScanner = new ConfigScanner();

  public async scan(
    files: ScannedFile[],
    targetName: string = 'Local Workspace',
    targetType: 'GITHUB_REPO' | 'LOCAL_FILES' | 'SNIPPET' | 'REPO' | 'FILES' = 'LOCAL_FILES',
    targetUrl: string = '',
    initialCoverage?: Partial<ScanCoverage>
  ): Promise<ScanResult> {
    const startTime = Date.now();

    const validFiles: ScannedFile[] = [];
    const skippedFiles: { path: string; reason: string }[] = [];

    // Filter and sanitize files
    for (const file of files) {
      const decision = FileFilter.evaluate(file.path, file.content, file.sizeBytes || file.size);
      if (decision.shouldScan) {
        validFiles.push({
          ...file,
          language: decision.language,
        });
      } else {
        skippedFiles.push({
          path: file.path,
          reason: decision.reason || 'Skipped by safety filter',
        });
      }
    }

    // 1. Run all modular static scanners
    const secretFindings = this.secretScanner.scanFiles(validFiles);
    const patternFindings = this.patternScanner.scanFiles(validFiles);
    const { findings: depFindings, manifests: depManifests } = this.dependencyScanner.scanFiles(validFiles);
    const configFindings = this.configScanner.scanFiles(validFiles);

    const rawFindings: SecurityFinding[] = [
      ...secretFindings,
      ...patternFindings,
      ...depFindings,
      ...configFindings,
    ];

    // Centralized evidence sanitization across ALL findings
    const sanitizedFindings = rawFindings.map((f) => {
      const sanitized = EvidenceSanitizer.sanitizeFinding(f);
      if (!sanitized.vulnerableSnippet && sanitized.snippet) {
        sanitized.vulnerableSnippet = sanitized.snippet;
      }
      if (!sanitized.fixedSnippet && sanitized.remediationSnippet) {
        sanitized.fixedSnippet = sanitized.remediationSnippet;
      }
      if (!sanitized.cvssScore) {
        sanitized.cvssScore =
          sanitized.severity === 'CRITICAL'
            ? 9.8
            : sanitized.severity === 'HIGH'
            ? 8.4
            : sanitized.severity === 'MEDIUM'
            ? 5.5
            : 3.0;
      }
      return sanitized;
    });

    // O(n) Deterministic Finding Deduplication
    const findingMap = new Map<string, SecurityFinding>();
    for (const f of sanitizedFindings) {
      const dedupKey = `${f.category}|${f.title}|${f.filePath}|${f.startLine}|${f.endLine}|${f.cwe || ''}`;
      if (!findingMap.has(dedupKey)) {
        findingMap.set(dedupKey, f);
      }
    }
    const deduplicatedFindings = Array.from(findingMap.values());

    // Deterministic sort by severity priority (CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO) and file path
    const SEVERITY_WEIGHT: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 2,
      LOW: 3,
      INFORMATIONAL: 4,
      INFO: 4,
    };
    deduplicatedFindings.sort((a, b) => {
      const weightA = SEVERITY_WEIGHT[a.severity] ?? 99;
      const weightB = SEVERITY_WEIGHT[b.severity] ?? 99;
      if (weightA !== weightB) return weightA - weightB;
      if (a.filePath !== b.filePath) return a.filePath.localeCompare(b.filePath);
      return a.startLine - b.startLine;
    });

    // Enforce hard upper bound on per-scan finding count
    const findingsTruncated = deduplicatedFindings.length > MAX_TOTAL_FINDINGS;
    const allFindings = findingsTruncated
      ? deduplicatedFindings.slice(0, MAX_TOTAL_FINDINGS)
      : deduplicatedFindings;

    const isCoverageComplete =
      (initialCoverage?.isComplete !== false) && !findingsTruncated;

    const coverage: ScanCoverage = {
      isComplete: isCoverageComplete,
      filesScanned: validFiles.length,
      totalDiscoveredFiles: initialCoverage?.totalDiscoveredFiles || files.length,
      candidateLimitReached: !!initialCoverage?.candidateLimitReached,
      truncatedByGithub: !!initialCoverage?.truncatedByGithub,
      truncatedByScanLimits: findingsTruncated || !!initialCoverage?.truncatedByScanLimits,
      reason: findingsTruncated
        ? `Maximum per-scan finding limit (${MAX_TOTAL_FINDINGS}) reached. Additional findings were truncated for safety.`
        : initialCoverage?.reason,
    };

    // Compute lines analyzed
    const linesCount = validFiles.reduce(
      (acc, f) => acc + (f.content ? f.content.split('\n').length : 0),
      0
    );
    const duration = Date.now() - startTime;

    // Calculate deterministic security metrics
    const metrics = ScoreCalculator.calculate(allFindings, validFiles.length, linesCount, duration);

    // Build Executive Summary
    const criticalCount = metrics.criticalCount;
    const highCount = metrics.highCount;

    let executiveOverview = '';
    if (allFindings.length === 0) {
      executiveOverview = 'No security vulnerabilities, exposed secrets, or misconfigurations were detected.';
    } else {
      executiveOverview = `Audit identified ${allFindings.length} security finding(s) across ${validFiles.length} file(s) with ${criticalCount} Critical and ${highCount} High severity item(s).`;
    }

    const primaryRiskVectors: string[] = [];
    if (secretFindings.length > 0) primaryRiskVectors.push(`${secretFindings.length} hardcoded credential(s) or API token(s) exposed in source code.`);
    if (patternFindings.some((p) => p.cwe?.includes('89') || p.cwe?.includes('78'))) primaryRiskVectors.push('Injection vulnerabilities (SQLi / Command Injection) risking unauthorized execution.');
    if (patternFindings.some((p) => p.cwe?.includes('502'))) primaryRiskVectors.push('Insecure deserialization leading to Remote Code Execution.');
    if (patternFindings.some((p) => p.cwe?.includes('79'))) primaryRiskVectors.push('Cross-Site Scripting (XSS) via unescaped DOM rendering.');
    if (depFindings.length > 0) primaryRiskVectors.push(`${depFindings.length} unpinned or vulnerable third-party dependencies.`);
    if (configFindings.length > 0) primaryRiskVectors.push(`${configFindings.length} configuration hardening issue(s) identified.`);
    if (primaryRiskVectors.length === 0 && allFindings.length > 0) primaryRiskVectors.push('Security improvements recommended.');

    const remediationPriorities: string[] = [];
    if (secretFindings.length > 0) remediationPriorities.push('Immediately revoke and rotate all leaked API keys/tokens and inject via environment variables.');
    if (patternFindings.length > 0) remediationPriorities.push('Apply parameterized queries and avoid invoking shell commands directly with untrusted input.');
    if (depFindings.length > 0) remediationPriorities.push('Pin all third-party package dependencies to secure semantic versions.');
    remediationPriorities.push('Integrate automated static security checks into pre-commit and CI/CD pipelines.');

    return {
      scanId: `scan-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      timestamp: new Date().toISOString(),
      targetUrl,
      targetName,
      targetType: targetType as any,
      metrics,
      findings: allFindings,
      issues: allFindings,
      dependencyManifests: depManifests,
      coverage,
      executiveSummary: executiveOverview,
      keyRisks: primaryRiskVectors,
      immediateActions: remediationPriorities,
      summary: {
        executiveOverview,
        primaryRiskVectors,
        remediationPriorities,
      },
      scannedFilesList: validFiles.map((f) => f.path),
    };
  }
}
