import { describe, it } from 'node:test';
import assert from 'node:assert';
import { SecretScanner } from '../backend/scanner/secrets/secretScanner';
import { maskSecret, maskSnippet } from '../backend/scanner/utils/masking';
import { calculateShannonEntropy } from '../backend/scanner/utils/entropy';

describe('SecretScanner Test Suite', () => {
  const scanner = new SecretScanner();

  it('detects AWS Access Key ID with high confidence', () => {
    const awsFiles = [
      {
        path: 'src/config/aws.ts',
        content: 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";\nconst SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";',
        sizeBytes: 90,
      },
    ];
    const findings = scanner.scanFiles(awsFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('AWS Access Key ID')), true);
  });

  it('correctly masks secrets in raw and snippet formats without exposing sensitive values', () => {
    const rawKey = 'AKIAIOSFODNN7EXAMPLE';
    const masked = maskSecret(rawKey);
    assert.strictEqual(masked.includes('AKIAIOSFODNN7EXAMPLE'), false);
    assert.strictEqual(masked.includes('****'), true);

    const codeLine = 'const apiKey = "AKIAIOSFODNN7EXAMPLE";';
    const maskedCode = maskSnippet(codeLine, rawKey);
    assert.strictEqual(maskedCode.includes('AKIAIOSFODNN7EXAMPLE'), false);
  });

  it('detects GitHub Personal Access Tokens in deployment scripts', () => {
    const ghFiles = [
      {
        path: 'deploy.sh',
        content: 'export GITHUB_TOKEN="ghp_9876543210abcdefghijklmnopqrstuvwxyz"',
        sizeBytes: 60,
      },
    ];
    const findings = scanner.scanFiles(ghFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('GitHub Personal Access Token')), true);
  });

  it('detects OpenAI API Keys with high fidelity', () => {
    const openaiFiles = [
      {
        path: 'src/ai.ts',
        content: 'const openaiKey = "sk-proj-abc1234567890XYZabcdefghijklmnopqrstuvwxyz1234567890";',
        sizeBytes: 80,
      },
    ];
    const findings = scanner.scanFiles(openaiFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('OpenAI API Key')), true);
  });

  it('suppresses common placeholders and mock strings to avoid false positives', () => {
    const placeholderFiles = [
      {
        path: 'src/config.ts',
        content: 'const API_KEY = "YOUR_API_KEY";\nconst SECRET = "REDACTED";\nconst TEST = "example-key";',
        sizeBytes: 80,
      },
    ];
    const findings = scanner.scanFiles(placeholderFiles);
    assert.strictEqual(findings.length, 0);
  });

  it('calculates Shannon entropy to differentiate high-randomness tokens from repetitive strings', () => {
    const randomStr = 'd89f2b1a87e34c90af812cd3';
    const repetitiveStr = 'aaaaaaaaaaaaaaaaaaaaaaaa';
    assert.strictEqual(calculateShannonEntropy(randomStr) > 3.0, true);
    assert.strictEqual(calculateShannonEntropy(repetitiveStr), 0);
  });
});
