export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'INFORMATIONAL';

export type VulnerabilityCategory =
  | 'SECRETS_LEAK'
  | 'INJECTION'
  | 'BROKEN_AUTH'
  | 'SENSITIVE_DATA_EXPOSURE'
  | 'BROKEN_ACCESS_CONTROL'
  | 'SECURITY_MISCONFIG'
  | 'XSS'
  | 'INSECURE_DESERIALIZATION'
  | 'SSRF'
  | 'IAC_MISCONFIG'
  | 'DEPENDENCY_VULN'
  | 'SECRETS'
  | 'CODE_PATTERNS'
  | 'DEPENDENCIES'
  | 'CONFIGURATION'
  | string;

export type FindingCategory = VulnerabilityCategory;

export interface SecurityIssue {
  id: string;
  title: string;
  severity: Severity;
  category: VulnerabilityCategory;
  cwe?: string;
  cvssScore?: number;
  filePath: string;
  startLine: number;
  endLine: number;
  description: string;
  impact?: string;
  recommendation: string;
  vulnerableSnippet?: string;
  fixedSnippet?: string;
  patchExplanation?: string;
  confidence?: 'HIGH' | 'MEDIUM' | 'LOW';
  applied?: boolean;
  snippet?: string;
  maskedSnippet?: string;
  remediationSnippet?: string;
  metadata?: Record<string, any>;
}

export type SecurityFinding = SecurityIssue;

export interface CodeFile {
  path: string;
  content: string;
  size?: number;
  sizeBytes?: number;
  language?: string;
}

export interface DependencyManifestSummary {
  manifestPath: string;
  ecosystem: string;
  totalDependencies: number;
  flaggedDependencies: number;
}

export interface SecurityScanMetrics {
  score: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  totalIssues: number;
  linesAnalyzed: number;
  filesAnalyzed: number;
  scanDurationMs: number;
  verdict?: 'EXCELLENT' | 'VERY_GOOD' | 'NEEDS_ATTENTION' | 'RISKY' | 'CRITICAL_RISK';
  informationalCount?: number;
  totalFindings?: number;
  categoryBreakdown?: {
    secrets: number;
    codePatterns: number;
    dependencies: number;
    configuration: number;
  };
  scoreDeductions?: {
    category: string;
    points: number;
    reason: string;
  }[];
}

export type SecurityScoreMetrics = SecurityScanMetrics;

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
  targetName: string;
  targetType: 'REPO' | 'SNIPPET' | 'FILES' | 'GITHUB_REPO' | 'LOCAL_FILES';
  targetUrl?: string;
  metrics: SecurityScanMetrics;
  issues: SecurityIssue[];
  findings?: SecurityIssue[];
  coverage?: ScanCoverage;
  executiveSummary: string;
  keyRisks: string[];
  immediateActions: string[];
  dependencyManifests?: DependencyManifestSummary[];
  scannedFilesList?: string[];
  summary?: {
    executiveOverview: string;
    primaryRiskVectors: string[];
    remediationPriorities: string[];
  };
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant' | 'system';
  content: string;
  timestamp?: string;
}
