import { Router, Request, Response } from 'express';
import { SecurityScanEngine } from '../scanner/engine';
import { GoogleGenAI } from '@google/genai';
import {
  validateScanPayload,
  validateGitHubRepo,
  validateGitRef,
  validateLogicalPath,
  validateChatPayload,
  encodeRepoPath,
  prioritizeSecurityFiles,
  MAX_FETCH_FILES_LIMIT,
  MAX_TREE_ITEMS,
  MAX_TREE_BYTES,
  MAX_FILE_BYTES,
} from './validation';
import { sendSafeError } from './errors';
import { runWithConcurrency, fetchWithTimeoutAndLimit } from './fetchHelper';
import { createRateLimiter } from './rateLimiter';

export const apiRouter = Router();
const engine = new SecurityScanEngine();

// In-memory rate limiters for expensive and standard endpoints
export const expensiveScanLimiter = createRateLimiter({ windowMs: 60000, maxRequests: 30 });
export const generalMetadataLimiter = createRateLimiter({ windowMs: 60000, maxRequests: 60 });

// Lazy initialization for Gemini client
let genAIClient: GoogleGenAI | null = null;
function getGenAI(): GoogleGenAI | null {
  if (!genAIClient && process.env.GEMINI_API_KEY) {
    try {
      genAIClient = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
    } catch (e) {
      console.error('Failed to initialize GoogleGenAI client:', e);
    }
  }
  return genAIClient;
}

/**
 * Health Check Endpoint
 * Open for liveness probes without aggressive rate limiting
 */
apiRouter.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'GitHub Security Audit Engine',
  });
});

/**
 * Scan Files Endpoint
 * Hardened with strict file count, payload size, path validation, and duplicate handling
 */
apiRouter.post('/scan', expensiveScanLimiter.middleware, async (req: Request, res: Response) => {
  try {
    const validation = validateScanPayload(req.body);
    if (!validation.valid || !validation.files) {
      sendSafeError(res, validation.statusCode || 400, validation.error || 'Invalid scan payload.');
      return;
    }

    const initialCoverage = req.body?.coverage;

    const result = await engine.scan(
      validation.files,
      validation.targetName,
      validation.targetType,
      validation.targetUrl,
      initialCoverage
    );

    res.json(result);
  } catch (error: unknown) {
    sendSafeError(res, 500, 'Security scan execution failed.', error);
  }
});

/**
 * GitHub Repo Info Endpoint
 * Hardened with repository name validation, bounded timeout, and safe error disclosure
 */
apiRouter.get('/github/repo-info', generalMetadataLimiter.middleware, async (req: Request, res: Response) => {
  const repoParam = req.query.repo as string;
  const validation = validateGitHubRepo(repoParam);
  if (!validation.valid) {
    sendSafeError(res, 400, validation.error || 'Invalid repository identifier.');
    return;
  }

  const { owner, repo } = validation;
  const githubApiUrl = `https://api.github.com/repos/${owner}/${repo}`;
  const headers: Record<string, string> = {
    'User-Agent': 'GitHub-Security-Scanner-Bot',
    Accept: 'application/vnd.github.v3+json',
  };

  if (process.env.GITHUB_TOKEN) {
    headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await fetch(githubApiUrl, {
      headers,
      signal: controller.signal,
    });

    if (!response.ok) {
      if (response.status === 404) {
        sendSafeError(res, 404, `Repository "${owner}/${repo}" was not found or is private.`);
        return;
      }
      if (response.status === 403) {
        sendSafeError(res, 403, 'GitHub API rate limit exceeded or access forbidden.');
        return;
      }
      sendSafeError(res, response.status, 'GitHub API returned an error response.');
      return;
    }

    const data: any = await response.json();

    res.json({
      fullName: data.full_name,
      name: data.name,
      owner: data.owner?.login,
      defaultBranch: data.default_branch || 'main',
      stars: data.stargazers_count,
      forks: data.forks_count,
      openIssues: data.open_issues_count,
      description: data.description,
      language: data.language,
      htmlUrl: data.html_url,
    });
  } catch (error: unknown) {
    sendSafeError(res, 500, 'Failed to contact GitHub API.', error);
  } finally {
    clearTimeout(timeoutId);
  }
});

/**
 * Filter relevant source code and config files for scanning
 */
const VALID_EXTENSIONS = [
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs',
  '.py', '.go', '.java', '.rb', '.php', '.cs', '.rs',
  '.json', '.yaml', '.yml', '.toml', '.env', '.env.example',
  '.sql', '.sh', '.bash', '.dockerfile',
];

function isTargetFile(pathStr: string): boolean {
  const lower = pathStr.toLowerCase();
  const fileName = lower.split('/').pop() || lower;

  if (
    lower.includes('node_modules/') ||
    lower.includes('.git/') ||
    lower.includes('dist/') ||
    lower.includes('build/') ||
    lower.includes('vendor/') ||
    lower.endsWith('.min.js') ||
    lower.endsWith('.min.css') ||
    lower.endsWith('.map')
  ) {
    return false;
  }

  if (
    fileName === 'dockerfile' ||
    fileName === 'package.json' ||
    fileName === 'requirements.txt' ||
    fileName === 'pyproject.toml' ||
    fileName === 'cargo.toml' ||
    fileName === 'gemfile' ||
    fileName === 'composer.json' ||
    fileName === 'go.mod' ||
    fileName.startsWith('.env')
  ) {
    return true;
  }

  return VALID_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/**
 * GitHub Fetch Files Endpoint
 * Hardened with:
 * - Branch name validation
 * - Clamped maxFiles bounds
 * - Bounded Git tree traversal
 * - Bounded concurrency (6 workers)
 * - Per-file timeout and streaming byte-size ceiling
 */
apiRouter.post('/github/fetch-files', expensiveScanLimiter.middleware, async (req: Request, res: Response) => {
  try {
    const { repoFullName, branch = 'main', maxFiles = 25 } = req.body;

    const repoValidation = validateGitHubRepo(repoFullName);
    if (!repoValidation.valid) {
      sendSafeError(res, 400, repoValidation.error || 'Invalid repository identifier.');
      return;
    }

    const branchValidation = validateGitRef(branch);
    if (!branchValidation.valid || !branchValidation.branch) {
      sendSafeError(res, 400, branchValidation.error || 'Invalid branch or Git reference.');
      return;
    }

    const { owner, repo } = repoValidation;
    const safeBranch = branchValidation.branch;

    // Enforce integer bound on maxFiles (1 to MAX_FETCH_FILES_LIMIT)
    const rawMax = Number(maxFiles);
    const safeMaxFiles = Number.isInteger(rawMax) && rawMax > 0 ? Math.min(rawMax, MAX_FETCH_FILES_LIMIT) : 25;

    const treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(safeBranch)}?recursive=1`;
    const headers: Record<string, string> = {
      'User-Agent': 'GitHub-Security-Scanner-Bot',
      Accept: 'application/vnd.github.v3+json',
    };

    if (process.env.GITHUB_TOKEN) {
      headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
    }

    const treeFetch = await fetchWithTimeoutAndLimit(treeUrl, {
      timeoutMs: 12000,
      maxBytes: MAX_TREE_BYTES,
      headers,
    });

    if (!treeFetch.ok || !treeFetch.content) {
      sendSafeError(
        res,
        treeFetch.status || 502,
        `Failed to fetch Git tree from GitHub for branch "${safeBranch}".`
      );
      return;
    }

    let treeData: any;
    try {
      treeData = JSON.parse(treeFetch.content);
    } catch {
      sendSafeError(res, 502, 'Malformed Git tree response from GitHub.');
      return;
    }

    const rawTreeItems = Array.isArray(treeData.tree) ? treeData.tree.slice(0, MAX_TREE_ITEMS) : [];
    const truncatedByGithub = !!treeData.truncated;

    // Filter only genuine blob/file entries with valid logical paths
    const candidateNodes: { path: string; size?: number }[] = [];
    for (const item of rawTreeItems) {
      if (
        item &&
        typeof item === 'object' &&
        item.type === 'blob' &&
        typeof item.path === 'string' &&
        validateLogicalPath(item.path).valid &&
        isTargetFile(item.path)
      ) {
        // Skip files that upstream reports as exceeding size limit
        if (typeof item.size === 'number' && item.size > MAX_FILE_BYTES) {
          continue;
        }

        candidateNodes.push({
          path: item.path,
          size: typeof item.size === 'number' ? item.size : undefined,
        });
      }
    }

    if (candidateNodes.length === 0) {
      sendSafeError(res, 404, 'No scan-compatible code or configuration files found.');
      return;
    }

    // Prioritize security-sensitive files (.env*, CI workflows, Dockerfiles, manifests)
    const prioritizedCandidates = prioritizeSecurityFiles(candidateNodes);
    const candidateLimitReached = prioritizedCandidates.length > safeMaxFiles;
    const targetNodes = prioritizedCandidates.slice(0, safeMaxFiles);

    // Download files using bounded concurrency (6 workers) with explicit timeout and size limits
    const fetchedFiles = await runWithConcurrency(targetNodes, 6, async (node) => {
      const safePath = encodeRepoPath(node.path);
      const rawUrl = `https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(safeBranch)}/${safePath}`;
      const fetchResult = await fetchWithTimeoutAndLimit(rawUrl, {
        timeoutMs: 10000,
        maxBytes: MAX_FILE_BYTES,
        headers: { 'User-Agent': 'GitHub-Security-Scanner-Bot' },
      });

      if (!fetchResult.ok || !fetchResult.content) {
        return null;
      }

      return {
        path: node.path,
        content: fetchResult.content,
        sizeBytes: fetchResult.sizeBytes || Buffer.byteLength(fetchResult.content, 'utf8'),
      };
    });

    const validFiles = fetchedFiles.filter(
      (f): f is { path: string; content: string; sizeBytes: number } => f !== null
    );

    const coverage = {
      isComplete: !candidateLimitReached && !truncatedByGithub,
      totalDiscoveredFiles: candidateNodes.length,
      filesScanned: validFiles.length,
      candidateLimitReached,
      truncatedByGithub,
      reason: candidateLimitReached
        ? `Candidate limit reached. First ${safeMaxFiles} files scanned; security-critical files were prioritized.`
        : truncatedByGithub
        ? 'Git tree response was truncated by GitHub API upstream.'
        : undefined,
    };

    res.json({
      repo: `${owner}/${repo}`,
      branch: safeBranch,
      filesCount: validFiles.length,
      files: validFiles,
      coverage,
    });
  } catch (error: unknown) {
    sendSafeError(res, 500, 'Failed to fetch repository files.', error);
  }
});

/**
 * AI Security Copilot Chat Endpoint
 * Hardened with query length validation, safe error boundaries, and rate limiting
 */
apiRouter.post('/chat', expensiveScanLimiter.middleware, async (req: Request, res: Response) => {
  try {
    const chatValidation = validateChatPayload(req.body);
    if (!chatValidation.valid || !chatValidation.value) {
      sendSafeError(res, chatValidation.statusCode || 400, chatValidation.error || 'Invalid chat payload.');
      return;
    }

    const { messages, codeContext, activeIssue, userQuery } = chatValidation.value;

    const ai = getGenAI();

    if (ai) {
      try {
        const systemInstruction = `You are a Principal Application Security Engineer and AppSec Architect.
You help developers identify, exploit, mitigate, and test security vulnerabilities in source code.

Context Information:
- Current Target File: ${codeContext?.currentFile ? String(codeContext.currentFile).slice(0, 200) : 'N/A'}
- Active Vulnerability Finding: ${
          activeIssue
            ? `${activeIssue.title || 'Finding'} (Severity: ${activeIssue.severity || 'HIGH'}, CWE: ${activeIssue.cwe || 'N/A'}, Line: ${activeIssue.startLine || '1'})`
            : 'No specific issue selected'
        }
- Vulnerability Description: ${activeIssue?.description ? String(activeIssue.description).slice(0, 500) : 'N/A'}
- Recommended Fix: ${activeIssue?.recommendation ? String(activeIssue.recommendation).slice(0, 500) : 'N/A'}

Provide clear, concrete, production-grade security advice. If generating code patches or unit tests, use standard markdown code blocks with clear inline annotations.`;

        const formattedHistory = messages
          .slice(0, -1)
          .filter((m: any) => m && typeof m.content === 'string')
          .map((m: any) => ({
            role: m.role === 'assistant' ? 'model' : 'user',
            parts: [{ text: String(m.content).slice(0, 5000) }],
          }));

        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: [
            ...formattedHistory,
            {
              role: 'user',
              parts: [
                {
                  text: `${userQuery}\n\n[Active Code Snippet Context]:\n\`\`\`\n${
                    typeof codeContext?.content === 'string' ? codeContext.content.slice(0, 5000) : ''
                  }\n\`\`\``,
                },
              ],
            },
          ],
          config: {
            systemInstruction,
            temperature: 0.2,
          },
        });

        if (response && response.text) {
          res.json({ reply: response.text });
          return;
        }
      } catch (geminiError) {
        console.error('Gemini API query error, falling back to rule reasoning:', geminiError);
      }
    }

    // Heuristic AppSec Advisor fallback response
    let fallbackReply = '';
    const qLower = userQuery.toLowerCase();

    if (qLower.includes('test') || qLower.includes('unit')) {
      fallbackReply = `### Automated Security Regression Test

Here is a recommended test suite pattern to verify remediation:

\`\`\`typescript
import request from 'supertest';
import app from '../src/app';

describe('Security Verification Test', () => {
  it('should reject malicious payloads and prevent injection', async () => {
    const maliciousPayload = "' OR '1'='1";
    const res = await request(app)
      .get('/api/users/search')
      .query({ q: maliciousPayload });

    expect(res.status).not.toBe(500);
    // Ensure no unauthorized records leaked
    expect(res.body).toEqual([]);
  });
});
\`\`\`
`;
    } else if (qLower.includes('exploit') || qLower.includes('attack') || qLower.includes('vector')) {
      fallbackReply = `### Attack Vector & Threat Model Analysis

1. **Vulnerability Type**: ${activeIssue?.title || 'Security Vulnerability'}
2. **Impact Severity**: **${activeIssue?.severity || 'HIGH'}** (${activeIssue?.cwe || 'CWE Generic'})
3. **Exploitation Mechanics**:
   - Attackers supply tailored strings with metacharacters (e.g. \`'\`, \`--\`, \`;\`, \`../\`, \`$(...)\`).
   - The unvalidated input escapes query or execution boundaries and is interpreted directly by the underlying engine.
4. **Defense in Depth**:
   - Parameterize all inputs.
   - Enforce least privilege credentials.
   - Deploy runtime WAF protection and CSP headers.`;
    } else if (qLower.includes('ci') || qLower.includes('cd') || qLower.includes('pipeline')) {
      fallbackReply = `### CI/CD Security Gate Recommendation

Add automated security checks to your GitHub Actions workflow (\`.github/workflows/security.yml\`):

\`\`\`yaml
name: Security Audit Pipeline
on: [push, pull_request]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Install & Run Security Scanner
        run: |
          npm ci
          npm test
\`\`\`
`;
    } else {
      fallbackReply = `### AppSec Guidance: ${activeIssue?.title || 'Code Security Review'}

**Recommendation:**
${activeIssue?.recommendation || 'Ensure all inputs are strictly sanitized and credentials stored in secret managers.'}

**Security Checklist:**
- [x] Rotate any leaked credentials immediately in cloud consoles.
- [x] Use parameterized queries with bind variables.
- [x] Pin dependencies to fixed, audited versions.
- [x] Enforce principle of least privilege on runtime containers.`;
    }

    res.json({ reply: fallbackReply });
  } catch (error: unknown) {
    sendSafeError(res, 500, 'Failed to process security query.', error);
  }
});
