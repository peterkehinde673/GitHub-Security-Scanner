import { describe, it } from 'node:test';
import assert from 'node:assert';
import { CodePatternScanner } from '../backend/scanner/code-patterns/patternScanner';

describe('CodePatternScanner Test Suite', () => {
  const scanner = new CodePatternScanner();

  it('detects unparameterized SQL Injection concatenated in SQL queries as CRITICAL severity', () => {
    const sqliFiles = [
      {
        path: 'src/controllers/user.ts',
        content: `
        export async function getUser(req, res) {
          const query = "SELECT * FROM users WHERE id = '" + req.query.id + "'";
          const result = await db.query(query);
          return res.json(result);
        }
        `,
        sizeBytes: 150,
      },
    ];
    const findings = scanner.scanFiles(sqliFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('SQL Injection') && f.severity === 'CRITICAL'), true);
  });

  it('detects OS Command Injection (Python os.system) as CRITICAL severity', () => {
    const cmdFiles = [
      {
        path: 'utils/runner.py',
        content: `
        import os
        def run_cmd(user_arg):
            os.system("ping -c 1 " + user_arg)
        `,
        sizeBytes: 80,
      },
    ];
    const findings = scanner.scanFiles(cmdFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('Command Injection') && f.severity === 'CRITICAL'), true);
  });

  it('detects React Cross-Site Scripting via dangerouslySetInnerHTML', () => {
    const xssFiles = [
      {
        path: 'src/components/UserProfile.tsx',
        content: `
        export function UserProfile({ rawHtml }: { rawHtml: string }) {
          return <div dangerouslySetInnerHTML={{ __html: rawHtml }} />;
        }
        `,
        sizeBytes: 120,
      },
    ];
    const findings = scanner.scanFiles(xssFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('dangerouslySetInnerHTML') && f.severity === 'HIGH'), true);
  });

  it('detects Insecure Python Deserialization with pickle.loads', () => {
    const pickleFiles = [
      {
        path: 'service/worker.py',
        content: `
        import pickle
        def load_session(data):
            return pickle.loads(data)
        `,
        sizeBytes: 80,
      },
    ];
    const findings = scanner.scanFiles(pickleFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('Pickle') && f.severity === 'CRITICAL'), true);
  });

  it('detects Disabled TLS/SSL Certificate Verification', () => {
    const tlsFiles = [
      {
        path: 'src/apiClient.ts',
        content: `
        import https from 'https';
        const agent = new https.Agent({ rejectUnauthorized: false });
        `,
        sizeBytes: 80,
      },
    ];
    const findings = scanner.scanFiles(tlsFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('Disabled TLS') && f.severity === 'CRITICAL'), true);
  });
});
