import { describe, it } from 'node:test';
import assert from 'node:assert';
import { EvidenceSanitizer } from '../backend/scanner/sanitizer/evidenceSanitizer';
import { SecurityScanEngine } from '../backend/scanner/engine';
import { SecretScanner } from '../backend/scanner/secrets/secretScanner';
import { CodePatternScanner } from '../backend/scanner/code-patterns/patternScanner';
import {
  encodeRepoPath,
  prioritizeSecurityFiles,
  validateChatPayload,
  MAX_CHAT_MESSAGES,
  MAX_USER_MESSAGE_CHARS,
  MAX_TOTAL_CONVERSATION_CHARS,
  MAX_CODE_CONTEXT_CHARS,
  MAX_ACTIVE_ISSUE_CHARS,
} from '../backend/api/validation';
import { ScoreCalculator } from '../backend/scanner/scoring/scoreCalculator';
import { SecurityFinding } from '../backend/scanner/types';

describe('Hardening Regression Test Suite', () => {
  // 1. Evidence Sanitizer Tests
  describe('P0-2: Evidence Sanitizer & Redaction', () => {
    it('redacts raw AWS keys, GitHub tokens, and private keys from snippets and descriptions', () => {
      const finding: SecurityFinding = {
        id: 'test-1',
        title: 'Exposed Key AKIAIOSFODNN7EXAMPLE in Config',
        category: 'SECRETS',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        filePath: 'config.ts',
        startLine: 10,
        endLine: 10,
        description: 'Found raw token ghp_1234567890abcdefghijklmnopqrstuvwxyz12',
        recommendation: 'Rotate key AKIAIOSFODNN7EXAMPLE immediately',
        impact: 'Attacker accessed slack webhook https://example.invalid/slack-webhook',
        snippet: 'const awsKey = "AKIAIOSFODNN7EXAMPLE";',
        remediationSnippet: 'const awsKey = process.env.AWS_KEY;',
      };

      const sanitized = EvidenceSanitizer.sanitizeFinding(finding);

      assert.strictEqual(sanitized.snippet?.includes('AKIAIOSFODNN7EXAMPLE'), false);
      assert.strictEqual(sanitized.snippet?.includes('AKIA****************'), true);
      assert.strictEqual(sanitized.title.includes('AKIAIOSFODNN7EXAMPLE'), false);
      assert.strictEqual(sanitized.title.includes('AKIA****************'), true);
      assert.strictEqual(sanitized.description.includes('ghp_1234567890abcdefghijklmnopqrstuvwxyz12'), false);
      assert.strictEqual(sanitized.recommendation.includes('AKIAIOSFODNN7EXAMPLE'), false);
      assert.strictEqual(sanitized.impact?.includes('https://example.invalid/slack-webhook'), false);
    });

    it('redacts private key blocks from evidence snippets', () => {
      const privateKeyText = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y...\n-----END RSA PRIVATE KEY-----';
      const finding: SecurityFinding = {
        id: 'test-key',
        title: 'Private Key Found',
        category: 'SECRETS',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        impact: 'Unauthorized access to encrypted data',
        filePath: 'cert.pem',
        startLine: 1,
        endLine: 3,
        description: 'Hardcoded private RSA key',
        recommendation: 'Use KMS',
        snippet: privateKeyText,
      };

      const sanitized = EvidenceSanitizer.sanitizeFinding(finding);
      assert.strictEqual(sanitized.snippet?.includes('MIIEowIBAAKCAQEA0Y'), false);
      assert.strictEqual(sanitized.snippet?.includes('[REDACTED_PRIVATE_KEY]'), true);
    });
  });

  // 2. Deterministic Deduplication and Bounds in SecurityScanEngine
  describe('P0-3 & P0-4: Finding Deduplication and Scan Bounds', () => {
    it('deduplicates identical findings deterministically using composite identity', async () => {
      const engine = new SecurityScanEngine();

      const duplicateFindingsCode = [
        {
          path: 'src/app.ts',
          content: `
            // Intentionally repeated dangerous sink
            eval(userInput);
            eval(userInput);
          `,
        },
      ];

      const result = await engine.scan(duplicateFindingsCode, 'TestTarget', 'FILES');
      // Verify findings have unique IDs and composite identity keys
      const keys = new Set<string>();
      for (const finding of result.findings) {
        const key = `${finding.category}|${finding.title}|${finding.filePath}|${finding.startLine}|${finding.endLine}|${finding.cwe || ''}`;
        assert.strictEqual(keys.has(key), false, `Duplicate finding detected for key: ${key}`);
        keys.add(key);
      }
    });

    it('enforces maximum 20 matches per rule per file in SecretScanner', () => {
      const scanner = new SecretScanner();
      // Generate a file with 40 identical AWS keys
      const lines: string[] = [];
      for (let i = 0; i < 40; i++) {
        lines.push(`const k${i} = "AKIA${'A'.repeat(16)}";`);
      }

      const files = [{ path: 'secrets.ts', content: lines.join('\n') }];
      const findings = scanner.scanFiles(files);

      // Should be clamped to at most 20 matches for the AWS key rule
      const awsFindings = findings.filter((f) => f.title.includes('AWS'));
      assert.ok(awsFindings.length <= 20, `Expected <= 20 findings, got ${awsFindings.length}`);
    });

    it('enforces maximum 20 matches per rule per file in CodePatternScanner', () => {
      const scanner = new CodePatternScanner();
      // Generate a file with 40 eval calls
      const lines: string[] = [];
      for (let i = 0; i < 40; i++) {
        lines.push(`eval(req.query.cmd${i});`);
      }

      const files = [{ path: 'evals.ts', content: lines.join('\n') }];
      const findings = scanner.scanFiles(files);

      const evalFindings = findings.filter((f) => f.title.includes('eval()'));
      assert.ok(evalFindings.length <= 20, `Expected <= 20 findings, got ${evalFindings.length}`);
    });

    it('enforces upper bound cap of 500 total findings on ScanResult and marks coverage truncated', async () => {
      const engine = new SecurityScanEngine();

      // Create files that produce hundreds of findings
      const files: { path: string; content: string }[] = [];
      for (let f = 0; f < 30; f++) {
        const lines: string[] = [];
        for (let l = 0; l < 20; l++) {
          lines.push(`eval(param${l});`);
        }
        files.push({
          path: `src/vuln_file_${f}.js`,
          content: lines.join('\n'),
        });
      }

      const result = await engine.scan(files, 'Massive Findings Test', 'FILES');
      assert.ok(result.findings.length <= 500, `Findings length ${result.findings.length} should not exceed 500`);
      assert.strictEqual(result.coverage?.isComplete, false);
      assert.strictEqual(result.coverage?.truncatedByScanLimits, true);
    });
  });

  // 3. File Prioritization and Path Encoding
  describe('P0-5 & P0-6: Prioritization & Safe Repo Path Encoding', () => {
    it('prioritizes security-critical files (.env, CI workflows, Dockerfiles, manifests)', () => {
      const candidateFiles = [
        { path: 'src/components/Button.tsx' },
        { path: 'src/utils/math.ts' },
        { path: '.env' },
        { path: 'Dockerfile' },
        { path: 'package.json' },
        { path: '.github/workflows/ci.yml' },
        { path: 'docs/README.md' },
      ];

      const prioritized = prioritizeSecurityFiles(candidateFiles);
      const topPaths = prioritized.slice(0, 4).map((f) => f.path);

      assert.ok(topPaths.includes('.env'), '.env should be in top priority files');
      assert.ok(topPaths.includes('.github/workflows/ci.yml'), 'Workflow should be in top priority files');
      assert.ok(topPaths.includes('Dockerfile'), 'Dockerfile should be in top priority files');
      assert.ok(topPaths.includes('package.json'), 'package.json should be in top priority files');
    });

    it('safely encodes repo paths while preserving directory slashes', () => {
      const testCases = [
        { input: 'src/components/My Code#1.ts', expected: 'src/components/My%20Code%231.ts' },
        { input: 'path/with?query&param=1.js', expected: 'path/with%3Fquery%26param%3D1.js' },
        { input: 'standard/path/file.py', expected: 'standard/path/file.py' },
        { input: 'assets/image with space.png', expected: 'assets/image%20with%20space.png' },
      ];

      for (const tc of testCases) {
        const encoded = encodeRepoPath(tc.input);
        assert.strictEqual(encoded, tc.expected);
      }
    });
  });

  // 4. Strict Chat Input Validation Bounds
  describe('P0-7: Strict Chat Input Validation & Context Bounds', () => {
    it('accepts valid, well-formed chat payloads within bounds', () => {
      const validPayload = {
        messages: [
          { role: 'user', content: 'How do I fix this SQL injection vulnerability?' },
        ],
        codeContext: {
          currentFile: 'src/users.ts',
          content: 'db.query("SELECT * FROM users WHERE id = " + id);',
        },
        activeIssue: {
          title: 'SQL Injection',
          severity: 'CRITICAL',
          cwe: 'CWE-89',
        },
      };

      const result = validateChatPayload(validPayload);
      assert.strictEqual(result.valid, true);
      assert.strictEqual(result.value?.userQuery, 'How do I fix this SQL injection vulnerability?');
    });

    it('rejects chat payloads with too many messages (> MAX_CHAT_MESSAGES)', () => {
      const tooManyMessages = Array.from({ length: MAX_CHAT_MESSAGES + 1 }, (_, i) => ({
        role: i % 2 === 0 ? 'user' : 'assistant',
        content: `Message ${i}`,
      }));

      const result = validateChatPayload({ messages: tooManyMessages });
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.statusCode, 400);
      assert.ok(result.error?.includes('exceeds maximum allowed count'));
    });

    it('rejects chat payloads with an individual message exceeding MAX_USER_MESSAGE_CHARS', () => {
      const payload = {
        messages: [
          { role: 'user', content: 'a'.repeat(MAX_USER_MESSAGE_CHARS + 1) },
        ],
      };

      const result = validateChatPayload(payload);
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.statusCode, 400);
      assert.ok(result.error?.includes('exceeds maximum length'));
    });

    it('rejects chat payloads with total conversation text exceeding MAX_TOTAL_CONVERSATION_CHARS', () => {
      // 5 messages of 3500 chars = 17,500 chars (> 16,000 chars limit)
      const messages = Array.from({ length: 5 }, (_, i) => ({
        role: i % 2 === 0 ? 'user' : 'assistant',
        content: 'm'.repeat(3500),
      }));

      const result = validateChatPayload({ messages });
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.statusCode, 400);
      assert.ok(result.error?.includes('exceeds maximum allowed limit'));
    });

    it('rejects chat payloads with codeContext content exceeding MAX_CODE_CONTEXT_CHARS', () => {
      const payload = {
        messages: [{ role: 'user', content: 'Explain this file' }],
        codeContext: {
          content: 'c'.repeat(MAX_CODE_CONTEXT_CHARS + 10),
        },
      };

      const result = validateChatPayload(payload);
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.statusCode, 400);
      assert.ok(result.error?.includes('codeContext content'));
    });

    it('rejects chat payloads with oversized activeIssue exceeding MAX_ACTIVE_ISSUE_CHARS', () => {
      const payload = {
        messages: [{ role: 'user', content: 'Explain this issue' }],
        activeIssue: {
          data: 'x'.repeat(MAX_ACTIVE_ISSUE_CHARS + 10),
        },
      };

      const result = validateChatPayload(payload);
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.statusCode, 400);
      assert.ok(result.error?.includes('activeIssue size'));
    });

    it('rejects chat payloads without a user message', () => {
      const payload = {
        messages: [
          { role: 'assistant', content: 'Hello there' },
        ],
      };

      const result = validateChatPayload(payload);
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.statusCode, 400);
      assert.ok(result.error?.includes('At least one user message'));
    });
  });

  // 5. Score Integrity & Metric Cleanup Tests
  describe('P0-10 & P0-11: Score Integrity & Metric Cleanup', () => {
    it('does not expose owaspCompliance or fabricated percentages in ScoreCalculator results', () => {
      const metrics = ScoreCalculator.calculate([], 10, 500, 100);
      assert.strictEqual((metrics as any).owaspCompliance, undefined);
      assert.strictEqual(metrics.score, 100);
      assert.strictEqual(metrics.verdict, 'EXCELLENT');
    });

    it('calculates deterministic deductions without artificial increments', () => {
      const findings: SecurityFinding[] = [
        {
          id: '1',
          category: 'INJECTION',
          severity: 'HIGH',
          confidence: 'HIGH',
          impact: 'Remote code execution or data exfiltration',
          title: 'SQL Injection',
          description: 'SQLi',
          recommendation: 'Fix',
          filePath: 'app.ts',
          startLine: 1,
          endLine: 2,
        },
      ];

      const metrics = ScoreCalculator.calculate(findings, 1, 50, 10);
      // High deduction is 15 points: 100 - 15 = 85 (Grade B: 75..87)
      assert.strictEqual(metrics.score, 85);
      assert.strictEqual(metrics.grade, 'B');
      assert.strictEqual(metrics.verdict, 'RISKY');
    });
  });
});
