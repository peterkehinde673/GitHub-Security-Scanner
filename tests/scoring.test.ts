import { describe, it } from 'node:test';
import assert from 'node:assert';
import { ScoreCalculator } from '../backend/scanner/scoring/scoreCalculator';
import { SecurityFinding } from '../backend/scanner/types';

describe('ScoreCalculator Test Suite', () => {
  const criticalFinding: SecurityFinding = {
    id: 'crit-1',
    category: 'SECRETS',
    severity: 'CRITICAL',
    title: 'AWS Key Leaked',
    description: 'Leaked AWS Key',
    impact: 'Full compromise',
    recommendation: 'Rotate key',
    filePath: 'aws.ts',
    startLine: 1,
    endLine: 1,
    confidence: 'HIGH',
  };

  it('awards 100 points, grade A+, and EXCELLENT verdict to clean code with 0 findings', () => {
    const cleanMetrics = ScoreCalculator.calculate([], 5, 250, 15);
    assert.strictEqual(cleanMetrics.score, 100);
    assert.strictEqual(cleanMetrics.grade, 'A+');
    assert.strictEqual(cleanMetrics.verdict, 'EXCELLENT');
  });

  it('deducts 25 points for a single CRITICAL finding resulting in score 75 and CRITICAL_RISK verdict', () => {
    const oneCritMetrics = ScoreCalculator.calculate([criticalFinding], 1, 20, 10);
    assert.strictEqual(oneCritMetrics.score, 75);
    assert.strictEqual(oneCritMetrics.criticalCount, 1);
    assert.strictEqual(oneCritMetrics.verdict, 'CRITICAL_RISK');
  });

  it('floors score at 0 for severe accumulations of vulnerabilities and assigns Grade F', () => {
    const multipleFindings: SecurityFinding[] = [
      criticalFinding,
      { ...criticalFinding, id: 'crit-2' },
      { ...criticalFinding, id: 'crit-3' },
      { ...criticalFinding, id: 'crit-4' },
      { ...criticalFinding, id: 'crit-5' },
    ];
    const floorMetrics = ScoreCalculator.calculate(multipleFindings, 2, 100, 20);
    assert.strictEqual(floorMetrics.score, 0);
    assert.strictEqual(floorMetrics.grade, 'F');
    assert.strictEqual(floorMetrics.verdict, 'CRITICAL_RISK');
  });
});
