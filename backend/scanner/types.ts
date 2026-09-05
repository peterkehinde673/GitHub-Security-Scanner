export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL' | 'INFO';

export type FindingCategory =
  | 'SECRETS'
  | 'CODE_PATTERNS'
  | 'DEPENDENCIES'
  | 'CONFIGURATION'
  | 'SECRETS_LEAK'
  | 'INJECTION'
  | 'XSS'
  | 'DEPENDENCY_VULN'
  | 'SECURITY_MISCONFIG'
  | string;

export interface SecurityFinding {
  id: string;
  category: FindingCategory;
  severity: Severity;
  title: string;
  description: string;
  impact: string;
  recommendation: string;
  filePath: string;
  startLine: number;
  endLine: number;
  cwe?: string;
  cvssScore?: number;
  snippet?: string;
  maskedSnippet?: string;
  confidence: 'HIGH' | 'MEDIUM' | 'LOW';
  remediationSnippet?: string;
  metadata?: Record<string, any>;
  vulnerableSnippet?: string;
  fixedSnippet?: string;
  applied?: boolean;
}

export interface ScannedFile {
  path: string;
  content: string;
  sizeBytes?: number;
  size?: number;
  language?: string;
}

export interface DependencyManifestSummary {
  manifestPath: string;
  ecosystem: string;
  totalDependencies: number;
  flaggedDependencies: number;
}

export interface SecurityScoreMetrics {
  score: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  verdict: 'EXCELLENT' | 'VERY_GOOD' | 'NEEDS_ATTENTION' | 'RISKY' | 'CRITICAL_RISK';
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  informationalCount: number;
  infoCount?: number;
  totalFindings: number;
  totalIssues?: number;
  categoryBreakdown: {
    secrets: number;
    codePatterns: number;
    dependencies: number;
    configuration: number;
  };
  scoreDeductions: {
    category: string;
    points: number;
    reason: string;
  }[];
  filesAnalyzed: number;
  linesAnalyzed: number;
  scanDurationMs: number;
}

export interface ScanCoverage {
  isComplete: boolean;
  reason?: string;
  totalDiscoveredFiles?: number;
  filesScanned: number;
  candidateLimitReached?: boolean;
  truncatedByGithub?: boolean;
  truncatedByScanLimits?: boolean;
}

export interface ScanResult {
  scanId: string;
  timestamp: string;
  targetUrl: string;
  targetName: string;
  targetType: 'GITHUB_REPO' | 'LOCAL_FILES' | 'SNIPPET' | 'REPO' | 'FILES';
  metrics: SecurityScoreMetrics;
  findings: SecurityFinding[];
  issues?: SecurityFinding[];
  dependencyManifests: DependencyManifestSummary[];
  coverage?: ScanCoverage;
  executiveSummary?: string;
  keyRisks?: string[];
  immediateActions?: string[];
  summary: {
    executiveOverview: string;
    primaryRiskVectors: string[];
    remediationPriorities: string[];
  };
  scannedFilesList: string[];
}
