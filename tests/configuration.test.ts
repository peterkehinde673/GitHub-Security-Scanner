import { describe, it } from 'node:test';
import assert from 'node:assert';
import { ConfigScanner } from '../backend/scanner/configuration/configScanner';

describe('ConfigScanner Test Suite', () => {
  const scanner = new ConfigScanner();

  it('detects running as root user in Dockerfile', () => {
    const dockerFiles = [
      {
        path: 'Dockerfile',
        content: 'FROM node:18\nUSER root\nCMD ["node", "app.js"]',
        sizeBytes: 45,
      },
    ];
    const findings = scanner.scanFiles(dockerFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('Root User') || f.title.includes('root')), true);
  });

  it('detects debug mode enabled in production code (e.g. Flask)', () => {
    const flaskFiles = [
      {
        path: 'app.py',
        content: "app = Flask(__name__)\napp.config['DEBUG'] = True\napp.run()",
        sizeBytes: 50,
      },
    ];
    const findings = scanner.scanFiles(flaskFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('Debug Mode')), true);
  });

  it('detects wildcard/permissive CORS headers', () => {
    const corsFiles = [
      {
        path: 'server.js',
        content: "res.setHeader('Access-Control-Allow-Origin', '*');",
        sizeBytes: 45,
      },
    ];
    const findings = scanner.scanFiles(corsFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('CORS')), true);
  });

  it('detects committed active .env files containing production secrets', () => {
    const envFiles = [
      {
        path: '.env',
        content: 'DATABASE_URL=postgres://user:superSecretPass123@localhost:5432/db\nAPI_KEY=live_prod_abc987654321',
        sizeBytes: 80,
      },
    ];
    const findings = scanner.scanFiles(envFiles);
    assert.strictEqual(findings.some((f) => f.title.includes('Committed Environment Secret')), true);
  });
});
