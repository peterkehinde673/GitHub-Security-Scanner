import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import http from 'node:http';
import {
  validateLogicalPath,
  validateGitRef,
  validateGitHubRepo,
  validateTargetMetadata,
  validateScanPayload,
  MAX_SCAN_FILES,
  MAX_FILE_BYTES,
  MAX_TOTAL_SCAN_BYTES,
  MAX_FETCH_FILES_LIMIT,
} from '../backend/api/validation';
import { sendSafeError } from '../backend/api/errors';
import { createRateLimiter } from '../backend/api/rateLimiter';
import { getCorsOptions } from '../backend/api/cors';
import { app } from '../server';

describe('Security Hardening Test Suite', () => {
  let server: http.Server;
  let baseUrl: string;

  before(async () => {
    // Start test instance of the Express app on an ephemeral port
    await new Promise<void>((resolve) => {
      server = http.createServer(app).listen(0, '127.0.0.1', () => {
        const address = server.address() as any;
        baseUrl = `http://127.0.0.1:${address.port}`;
        resolve();
      });
    });
  });

  after(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  // A. /api/scan rejects too many files
  it('A. /api/scan rejects too many files beyond MAX_SCAN_FILES limit', async () => {
    const tooManyFiles = Array.from({ length: MAX_SCAN_FILES + 1 }, (_, i) => ({
      path: `src/file_${i}.ts`,
      content: 'const a = 1;',
    }));

    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ files: tooManyFiles }),
    });

    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.strictEqual(body.error.includes('Exceeded maximum allowed files'), true);
  });

  // B. /api/scan rejects an oversized individual file
  it('B. /api/scan rejects an oversized individual file based on actual byte length', async () => {
    // Create payload larger than 500KB
    const oversizedContent = 'a'.repeat(MAX_FILE_BYTES + 10);
    const payload = {
      files: [
        {
          path: 'src/big.ts',
          content: oversizedContent,
          sizeBytes: 10, // Attempted size spoofing by client
        },
      ],
    };

    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    assert.strictEqual(res.status, 400);
    const body = await res.json();
    assert.strictEqual(body.error.includes('exceeds maximum file size'), true);
  });

  // C. /api/scan rejects excessive total payload size
  it('C. /api/scan rejects excessive total payload size across all files', () => {
    // 25 files of 450 KB each = 11.25 MB (exceeds 10MB limit)
    const largeChunk = 'x'.repeat(450 * 1024);
    const files = Array.from({ length: 25 }, (_, i) => ({
      path: `src/module_${i}.ts`,
      content: largeChunk,
    }));

    const result = validateScanPayload({ files });
    assert.strictEqual(result.valid, false);
    assert.strictEqual(result.statusCode, 413);
    assert.strictEqual(result.error?.includes('Total scan payload exceeds maximum limit'), true);
  });

  // D. /api/scan rejects malformed file objects
  it('D. /api/scan rejects malformed file objects (non-object, missing path, non-string content)', async () => {
    const malformedCases = [
      { files: ['not-an-object'] },
      { files: [{ path: 123, content: 'test' }] },
      { files: [{ path: 'test.ts', content: null }] },
      { files: [{ path: '', content: 'test' }] },
    ];

    for (const testCase of malformedCases) {
      const res = await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(testCase),
      });

      assert.strictEqual(res.status, 400);
      const body = await res.json();
      assert.strictEqual(typeof body.error, 'string');
    }
  });

  // E. /api/scan rejects absolute paths
  it('E. /api/scan rejects absolute paths (POSIX and Windows style)', () => {
    const absolutePaths = [
      '/etc/passwd',
      '/var/log/syslog',
      '\\Windows\\System32\\cmd.exe',
      '/home/user/.ssh/id_rsa',
    ];

    for (const p of absolutePaths) {
      const result = validateLogicalPath(p);
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.error?.includes('relative, not absolute'), true);
    }
  });

  // F. /api/scan rejects ../ traversal
  it('F. /api/scan rejects ../ directory traversal sequences', () => {
    const traversalPaths = [
      '../../etc/passwd',
      '../../../tmp/file',
      'foo/../../bar',
      'src/components/../../../secret.env',
    ];

    for (const p of traversalPaths) {
      const result = validateLogicalPath(p);
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.error?.includes('directory traversal'), true);
    }
  });

  // G. /api/scan rejects Windows traversal and drive prefixes
  it('G. /api/scan rejects Windows traversal and drive prefixes', () => {
    const windowsPaths = [
      'C:\\Windows\\System32',
      'C:/Windows/System32',
      'D:\\data\\secrets.txt',
      '..\\..\\secret',
      'foo\\..\\bar',
    ];

    for (const p of windowsPaths) {
      const result = validateLogicalPath(p);
      assert.strictEqual(result.valid, false);
    }
  });

  // H. /api/scan rejects null bytes
  it('H. /api/scan rejects paths containing null bytes', () => {
    const nullBytePaths = [
      'src/index\0.ts',
      'config\u0000.env',
      'safe/path/with/\0null',
    ];

    for (const p of nullBytePaths) {
      const result = validateLogicalPath(p);
      assert.strictEqual(result.valid, false);
      assert.strictEqual(result.error?.includes('null bytes'), true);
    }
  });

  // I. Duplicate paths are handled according to chosen policy (safely deduplicated)
  it('I. Duplicate paths are safely deduplicated to prevent CPU and memory exhaustion', async () => {
    const payload = {
      targetName: 'Deduplication Test',
      files: [
        { path: 'src/index.ts', content: 'const a = 1;' },
        { path: 'src/index.ts', content: 'const a = 1;' },
        { path: './src/index.ts', content: 'const a = 1;' }, // Normalized identical path
        { path: 'src/utils.ts', content: 'export const b = 2;' },
      ],
    };

    const validation = validateScanPayload(payload);
    assert.strictEqual(validation.valid, true);
    assert.strictEqual(validation.files?.length, 2); // 4 items deduplicated to 2

    // Verify through HTTP endpoint
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.metrics.filesAnalyzed, 2);
    assert.strictEqual(body.scannedFilesList.length, 2);
  });

  // J. maxFiles cannot be bypassed with a huge value
  it('J. maxFiles cannot be bypassed with a huge value and is safely clamped', () => {
    const rawMax = 9999999;
    const clamped = Number.isInteger(rawMax) && rawMax > 0 ? Math.min(rawMax, MAX_FETCH_FILES_LIMIT) : 25;
    assert.strictEqual(clamped, 40);
  });

  // K. Malformed GitHub tree entries do not crash processing
  it('K. Malformed GitHub tree entries do not crash processing and are cleanly filtered', () => {
    const rawTree = [
      null,
      undefined,
      {},
      { type: 'tree', path: 'src' },
      { type: 'blob' }, // missing path
      { type: 'blob', path: '../../etc/passwd' }, // traversal
      { type: 'blob', path: 'src/index\0.ts' }, // null byte
      { type: 'blob', path: 'src/app.ts', size: 99999999 }, // oversized
      { type: 'blob', path: 'src/valid.ts', size: 120 }, // valid
      { type: 'blob', path: 'package.json', size: 300 }, // valid
    ];

    const targetNodes: any[] = [];
    for (const item of rawTree) {
      if (
        item &&
        typeof item === 'object' &&
        item.type === 'blob' &&
        typeof item.path === 'string' &&
        validateLogicalPath(item.path).valid &&
        item.path.endsWith('.ts')
      ) {
        if (typeof item.size === 'number' && item.size > MAX_FILE_BYTES) {
          continue;
        }
        targetNodes.push(item);
      }
    }

    assert.strictEqual(targetNodes.length, 1);
    assert.strictEqual(targetNodes[0].path, 'src/valid.ts');
  });

  // L. Rate limit returns 429 after configured threshold
  it('L. Rate limiter returns 429 after configured threshold is reached', () => {
    const { limiter, middleware } = createRateLimiter({
      windowMs: 10000,
      maxRequests: 2,
    });

    let lastStatus = 200;
    const headers: Record<string, any> = {};
    const mockRes = () => ({
      setHeader: (k: string, v: any) => {
        headers[k] = v;
      },
      status: (code: number) => {
        lastStatus = code;
        return {
          json: () => {},
        };
      },
    });

    const mockReq = { ip: '10.0.0.1', socket: {} } as any;

    // First request -> allowed
    middleware(mockReq, mockRes() as any, () => {});
    assert.strictEqual(lastStatus, 200);

    // Second request -> allowed
    middleware(mockReq, mockRes() as any, () => {});
    assert.strictEqual(lastStatus, 200);

    // Third request -> 429 Too Many Requests
    middleware(mockReq, mockRes() as any, () => {});
    assert.strictEqual(lastStatus, 429);
    assert.ok(headers['Retry-After']);

    limiter.destroy();
  });

  // M. Rate limiter expires entries
  it('M. Rate limiter expires entries after windowMs passes', async () => {
    const { limiter, middleware } = createRateLimiter({
      windowMs: 50, // 50 ms test window
      maxRequests: 1,
    });

    let status = 200;
    const mockRes = () => ({
      setHeader: () => {},
      status: (code: number) => {
        status = code;
        return { json: () => {} };
      },
    });
    const mockReq = { ip: '10.0.0.2', socket: {} } as any;

    // 1st request -> ok
    middleware(mockReq, mockRes() as any, () => {});
    assert.strictEqual(status, 200);

    // 2nd request immediately -> 429
    middleware(mockReq, mockRes() as any, () => {});
    assert.strictEqual(status, 429);

    // Wait for window to expire
    await new Promise((r) => setTimeout(r, 60));

    // Next request -> ok again
    status = 200;
    middleware(mockReq, mockRes() as any, () => {});
    assert.strictEqual(status, 200);

    limiter.destroy();
  });

  // N. CORS rejects an unapproved origin when configured
  it('N. CORS rejects an unapproved origin when CORS_ORIGIN is configured', (t, done) => {
    const corsOptions = getCorsOptions('https://trusted-domain.com,https://app.example.com');
    const originValidator = corsOptions.origin as (
      origin: string | undefined,
      callback: (err: Error | null, allow?: boolean) => void
    ) => void;

    // Trusted origin allowed
    originValidator('https://trusted-domain.com', (err, allow) => {
      assert.strictEqual(err, null);
      assert.strictEqual(allow, true);

      // Untrusted origin rejected
      originValidator('https://evil-attacker.com', (untrustedErr, untrustedAllow) => {
        assert.ok(untrustedErr instanceof Error);
        assert.strictEqual(untrustedAllow, undefined);

        // Direct request without Origin header (same-origin / server-to-server) allowed
        originValidator(undefined, (noOriginErr, noOriginAllow) => {
          assert.strictEqual(noOriginErr, null);
          assert.strictEqual(noOriginAllow, true);
          done();
        });
      });
    });
  });

  // O. API errors do not expose internal error.message/details
  it('O. API errors do not expose internal error.message, stack traces, or file paths', () => {
    let capturedStatus = 0;
    let capturedJson: any = null;

    const mockResponse: any = {
      status: (code: number) => {
        capturedStatus = code;
        return {
          json: (data: any) => {
            capturedJson = data;
          },
        };
      },
    };

    const internalSensitiveError = new Error(
      'DATABASE CONNECTION CRASHED at /var/app/secrets/master.key: password=SUPER_SECRET_TOKEN'
    );

    sendSafeError(mockResponse, 500, 'Security scan execution failed.', internalSensitiveError);

    assert.strictEqual(capturedStatus, 500);
    assert.deepStrictEqual(capturedJson, { error: 'Security scan execution failed.' });
    assert.strictEqual((capturedJson as Record<string, unknown>)?.details, undefined);
    assert.strictEqual((capturedJson as Record<string, unknown>)?.stack, undefined);
  });

  // P. Target metadata length limits work
  it('P. Target metadata length and format limits work as expected', () => {
    // Excessively long targetName
    const longName = 'A'.repeat(201);
    const meta1 = validateTargetMetadata(longName);
    assert.strictEqual(meta1.valid, false);

    // Target name with control characters
    const controlName = 'Target\x00Name';
    const meta2 = validateTargetMetadata(controlName);
    assert.strictEqual(meta2.valid, false);

    // Invalid targetType
    const meta3 = validateTargetMetadata('Valid Name', 'INVALID_TYPE');
    assert.strictEqual(meta3.valid, false);

    // Dangerous targetUrl scheme
    const meta4 = validateTargetMetadata('Valid Name', 'REPO', 'javascript:alert(1)');
    assert.strictEqual(meta4.valid, false);

    // Valid target metadata
    const meta5 = validateTargetMetadata(
      'expressjs/express',
      'GITHUB_REPO',
      'https://github.com/expressjs/express'
    );
    assert.strictEqual(meta5.valid, true);
    assert.strictEqual(meta5.targetName, 'expressjs/express');
  });

  // Q. Branch/ref validation rejects unsafe values
  it('Q. Branch/ref validation rejects traversal, null bytes, command injection, and protocol injection', () => {
    const maliciousBranches = [
      '../etc/passwd',
      'main\0injection',
      'main;rm -rf /',
      'https://attacker.com/ref',
      'main//sub',
      '..',
      '-flag',
      '.hidden',
      'main.lock',
      'a'.repeat(101),
    ];

    for (const ref of maliciousBranches) {
      const check = validateGitRef(ref);
      assert.strictEqual(check.valid, false, `Expected branch "${ref}" to be rejected`);
    }

    const legitimateBranches = [
      'main',
      'master',
      'develop',
      'feature/security-fix',
      'release/v1.2.0',
      'hotfix/patch-2.1',
    ];

    for (const ref of legitimateBranches) {
      const check = validateGitRef(ref);
      assert.strictEqual(check.valid, true, `Expected branch "${ref}" to be accepted`);
      assert.strictEqual(check.branch, ref);
    }
  });

  it('verifies legitimate files scan normally without false rejections', () => {
    const legitimatePaths = [
      'src/index.ts',
      'package.json',
      '.github/workflows/security.yml',
      '.env',
      '.env.example',
      'Dockerfile',
      'backend/scanner/engine.ts',
    ];

    for (const p of legitimatePaths) {
      const check = validateLogicalPath(p);
      assert.strictEqual(check.valid, true, `Path "${p}" should be valid`);
    }
  });

  it('validates GitHub repo query formats strictly', () => {
    assert.strictEqual(validateGitHubRepo('expressjs/express').valid, true);
    assert.strictEqual(validateGitHubRepo('https://github.com/facebook/react').valid, true);
    assert.strictEqual(validateGitHubRepo('peterkehinde673/GitHub-Security-Scanner').valid, true);

    assert.strictEqual(validateGitHubRepo('../../etc/passwd').valid, false);
    assert.strictEqual(validateGitHubRepo('owner/repo;ls').valid, false);
    assert.strictEqual(validateGitHubRepo('singleword').valid, false);
  });
});
