import { ScannedFile } from '../scanner/types';

export const MAX_SCAN_FILES = 200;
export const MAX_FILE_BYTES = 500 * 1024; // 500 KB per individual file
export const MAX_TOTAL_SCAN_BYTES = 10 * 1024 * 1024; // 10 MB total across scan payload
export const MAX_PATH_LENGTH = 1024;
export const MAX_TARGET_NAME_LENGTH = 200;
export const MAX_TARGET_URL_LENGTH = 2048;
export const MAX_BRANCH_LENGTH = 100;
export const MAX_TREE_ITEMS = 10000;
export const MAX_FETCH_FILES_LIMIT = 40;
export const MAX_TREE_BYTES = 2 * 1024 * 1024; // 2 MB maximum size for Git tree response

export const MAX_CHAT_MESSAGES = 20;
export const MAX_USER_MESSAGE_CHARS = 4000;
export const MAX_TOTAL_CONVERSATION_CHARS = 16000;
export const MAX_CODE_CONTEXT_CHARS = 4000;
export const MAX_ACTIVE_ISSUE_CHARS = 2000;

export const ALLOWED_TARGET_TYPES = [
  'GITHUB_REPO',
  'LOCAL_FILES',
  'SNIPPET',
  'REPO',
  'FILES',
] as const;

export type TargetType = (typeof ALLOWED_TARGET_TYPES)[number];

export interface ValidationResult<T> {
  valid: boolean;
  value?: T;
  error?: string;
  statusCode?: number;
}

/**
 * Validates a repository-relative logical file path.
 * Rejects traversal, Windows drive letters, absolute paths, null bytes,
 * control characters, and excessively long paths without weakening security via premature normalization.
 */
export function validateLogicalPath(rawPath: unknown): { valid: boolean; normalizedPath?: string; error?: string } {
  if (typeof rawPath !== 'string' || rawPath.trim() === '') {
    return { valid: false, error: 'File path must be a non-empty string.' };
  }

  if (rawPath.length > MAX_PATH_LENGTH) {
    return { valid: false, error: `File path exceeds maximum length of ${MAX_PATH_LENGTH} characters.` };
  }

  // Reject null bytes
  if (rawPath.includes('\0') || rawPath.includes('\u0000')) {
    return { valid: false, error: 'File path contains illegal null bytes.' };
  }

  // Reject control characters (\x00 - \x1f, \x7f)
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(rawPath)) {
    return { valid: false, error: 'File path contains illegal control characters.' };
  }

  // Reject Windows drive prefix (e.g. C:\ or C:/)
  if (/^[a-zA-Z]:[/|\\]/.test(rawPath)) {
    return { valid: false, error: 'File path must not contain Windows drive prefix.' };
  }

  // Reject absolute paths (starting with / or \)
  if (rawPath.startsWith('/') || rawPath.startsWith('\\')) {
    return { valid: false, error: 'File path must be relative, not absolute.' };
  }

  // Reject directory traversal sequences in both POSIX and Windows styles
  // Catches ../, ..\, /../, \..\, /.., \.., and starting ..
  if (/(?:^|[\\/])\.\.(?:[\\/]|$)/.test(rawPath)) {
    return { valid: false, error: 'File path must not contain directory traversal sequences (..).' };
  }

  // Reject root directory markers
  if (rawPath === '.' || rawPath === './' || rawPath === '.\\') {
    return { valid: false, error: 'File path must specify a target file, not the root directory.' };
  }

  // Clean canonical representation for the scanner
  const normalized = rawPath.replace(/^\.\//, '').replace(/\\/g, '/');

  return { valid: true, normalizedPath: normalized };
}

/**
 * Validates a Git branch or reference name.
 * Strictly prevents traversal, protocol injection, null bytes, and control characters.
 */
export function validateGitRef(rawRef: unknown): { valid: boolean; branch?: string; error?: string } {
  if (typeof rawRef !== 'string') {
    return { valid: false, error: 'Branch or Git ref must be a string.' };
  }

  const ref = rawRef.trim();
  if (ref.length === 0) {
    return { valid: false, error: 'Branch or Git ref cannot be empty.' };
  }

  if (ref.length > MAX_BRANCH_LENGTH) {
    return { valid: false, error: `Branch or Git ref exceeds maximum length of ${MAX_BRANCH_LENGTH} characters.` };
  }

  if (ref.includes('\0') || ref.includes('\u0000')) {
    return { valid: false, error: 'Branch or Git ref contains illegal null bytes.' };
  }

  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(ref)) {
    return { valid: false, error: 'Branch or Git ref contains illegal control characters.' };
  }

  if (ref.includes('..')) {
    return { valid: false, error: 'Branch or Git ref must not contain traversal sequences (..).' };
  }

  // Disallow colon, backslash, protocol markers, or leading/trailing slashes
  if (ref.includes(':') || ref.includes('\\') || ref.includes('//')) {
    return { valid: false, error: 'Branch or Git ref contains invalid characters.' };
  }

  // Standard Git ref naming: alphanumeric, underscores, hyphens, periods, and forward slashes between segments
  const GIT_REF_REGEX = /^[a-zA-Z0-9_.-]+(?:\/[a-zA-Z0-9_.-]+)*$/;
  if (!GIT_REF_REGEX.test(ref) || ref.startsWith('-') || ref.startsWith('.') || ref.endsWith('.lock')) {
    return { valid: false, error: 'Invalid branch or Git ref format.' };
  }

  return { valid: true, branch: ref };
}

/**
 * Validates and sanitizes GitHub owner/repository input string.
 * Strictly prevents command injection, path traversal, and protocol abuse.
 */
export function validateGitHubRepo(input: unknown): {
  valid: boolean;
  owner?: string;
  repo?: string;
  error?: string;
} {
  if (!input || typeof input !== 'string') {
    return { valid: false, error: 'Repository query is required.' };
  }

  const clean = input
    .trim()
    .replace(/^https?:\/\/github\.com\//i, '')
    .replace(/^\/+/, '')
    .replace(/\/+$/, '')
    .replace(/\.git$/i, '');

  if (clean.length > 150) {
    return { valid: false, error: 'Repository identifier is too long.' };
  }

  // Strictly allow only alphanumeric, hyphen, dot, underscore, and a single slash between owner and repo
  const repoRegex = /^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+$/;
  if (!repoRegex.test(clean)) {
    return { valid: false, error: 'Invalid repository format. Please provide "owner/repo" (e.g. expressjs/express).' };
  }

  const [owner, repo] = clean.split('/');
  if (!owner || !repo || owner === '.' || repo === '.' || owner === '..' || repo === '..') {
    return { valid: false, error: 'Invalid repository owner or name.' };
  }

  return { valid: true, owner, repo };
}

/**
 * Validates scan target metadata (name, type, url).
 */
export function validateTargetMetadata(
  targetName?: unknown,
  targetType?: unknown,
  targetUrl?: unknown
): {
  valid: boolean;
  targetName: string;
  targetType: TargetType;
  targetUrl: string;
  error?: string;
} {
  // 1. targetName validation
  let safeTargetName = 'Scanned Target';
  if (targetName !== undefined && targetName !== null) {
    if (typeof targetName !== 'string') {
      return {
        valid: false,
        targetName: '',
        targetType: 'LOCAL_FILES',
        targetUrl: '',
        error: 'targetName must be a string.',
      };
    }
    if (targetName.length > MAX_TARGET_NAME_LENGTH) {
      return {
        valid: false,
        targetName: '',
        targetType: 'LOCAL_FILES',
        targetUrl: '',
        error: `targetName exceeds maximum length of ${MAX_TARGET_NAME_LENGTH} characters.`,
      };
    }
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x1f\x7f]/.test(targetName)) {
      return {
        valid: false,
        targetName: '',
        targetType: 'LOCAL_FILES',
        targetUrl: '',
        error: 'targetName contains invalid control characters.',
      };
    }
    if (targetName.trim().length > 0) {
      safeTargetName = targetName.trim();
    }
  }

  // 2. targetType validation
  let safeTargetType: TargetType = 'LOCAL_FILES';
  if (targetType !== undefined && targetType !== null) {
    if (typeof targetType !== 'string' || !ALLOWED_TARGET_TYPES.includes(targetType as TargetType)) {
      return {
        valid: false,
        targetName: '',
        targetType: 'LOCAL_FILES',
        targetUrl: '',
        error: `Invalid targetType. Allowed values: ${ALLOWED_TARGET_TYPES.join(', ')}.`,
      };
    }
    safeTargetType = targetType as TargetType;
  }

  // 3. targetUrl validation
  let safeTargetUrl = '';
  if (targetUrl !== undefined && targetUrl !== null && targetUrl !== '') {
    if (typeof targetUrl !== 'string') {
      return {
        valid: false,
        targetName: '',
        targetType: 'LOCAL_FILES',
        targetUrl: '',
        error: 'targetUrl must be a string.',
      };
    }
    if (targetUrl.length > MAX_TARGET_URL_LENGTH) {
      return {
        valid: false,
        targetName: '',
        targetType: 'LOCAL_FILES',
        targetUrl: '',
        error: `targetUrl exceeds maximum length of ${MAX_TARGET_URL_LENGTH} characters.`,
      };
    }

    try {
      const parsed = new URL(targetUrl);
      if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
        return {
          valid: false,
          targetName: '',
          targetType: 'LOCAL_FILES',
          targetUrl: '',
          error: 'targetUrl must use http or https protocol.',
        };
      }
      safeTargetUrl = parsed.toString();
    } catch {
      return {
        valid: false,
        targetName: '',
        targetType: 'LOCAL_FILES',
        targetUrl: '',
        error: 'targetUrl must be a valid HTTP or HTTPS URL.',
      };
    }
  }

  return {
    valid: true,
    targetName: safeTargetName,
    targetType: safeTargetType,
    targetUrl: safeTargetUrl,
  };
}

/**
 * Validates the full POST /api/scan request body.
 * Enforces file count, individual byte sizes, total byte sizes, and logical path security.
 * Safely deduplicates identical file paths to prevent CPU/memory exhaustion.
 */
export function validateScanPayload(body: any): {
  valid: boolean;
  files?: ScannedFile[];
  targetName?: string;
  targetType?: TargetType;
  targetUrl?: string;
  error?: string;
  statusCode?: number;
} {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return {
      valid: false,
      statusCode: 400,
      error: 'Request body must be a JSON object.',
    };
  }

  const { files, targetName, targetType, targetUrl } = body;

  if (!files || !Array.isArray(files)) {
    return {
      valid: false,
      statusCode: 400,
      error: 'Payload must include a files array.',
    };
  }

  if (files.length === 0) {
    return {
      valid: false,
      statusCode: 400,
      error: 'No files provided for security scanning.',
    };
  }

  if (files.length > MAX_SCAN_FILES) {
    return {
      valid: false,
      statusCode: 400,
      error: `Exceeded maximum allowed files per scan (${MAX_SCAN_FILES}). Received: ${files.length}.`,
    };
  }

  // Validate target metadata
  const metaValidation = validateTargetMetadata(targetName, targetType, targetUrl);
  if (!metaValidation.valid) {
    return {
      valid: false,
      statusCode: 400,
      error: metaValidation.error,
    };
  }

  // Deduplicate and validate files
  // Strategy: Deduplicate identical logical paths keeping first valid occurrence.
  const pathMap = new Map<string, ScannedFile>();
  let totalBytes = 0;

  for (let i = 0; i < files.length; i++) {
    const file = files[i];

    if (!file || typeof file !== 'object' || Array.isArray(file)) {
      return {
        valid: false,
        statusCode: 400,
        error: `File at index ${i} is malformed (must be an object with path and content).`,
      };
    }

    if (typeof file.path !== 'string') {
      return {
        valid: false,
        statusCode: 400,
        error: `File at index ${i} has an invalid or missing path.`,
      };
    }

    const pathCheck = validateLogicalPath(file.path);
    if (!pathCheck.valid) {
      return {
        valid: false,
        statusCode: 400,
        error: `Invalid file path "${file.path}": ${pathCheck.error}`,
      };
    }

    if (typeof file.content !== 'string') {
      return {
        valid: false,
        statusCode: 400,
        error: `File content for "${file.path}" must be a string.`,
      };
    }

    // Validate sizeBytes if provided
    if (file.sizeBytes !== undefined && file.sizeBytes !== null) {
      if (typeof file.sizeBytes !== 'number' || !Number.isFinite(file.sizeBytes) || file.sizeBytes < 0) {
        return {
          valid: false,
          statusCode: 400,
          error: `Invalid sizeBytes for "${file.path}". Must be a non-negative number.`,
        };
      }
    }

    // Compute actual UTF-8 byte length directly rather than trusting client-reported sizeBytes
    const actualBytes = Buffer.byteLength(file.content, 'utf8');

    if (actualBytes > MAX_FILE_BYTES) {
      return {
        valid: false,
        statusCode: 400,
        error: `File "${file.path}" exceeds maximum file size of ${MAX_FILE_BYTES / 1024}KB (actual size: ${Math.ceil(
          actualBytes / 1024
        )}KB).`,
      };
    }

    const canonicalPath = pathCheck.normalizedPath!;

    // Deduplicate: If already seen, skip duplicate occurrence
    if (pathMap.has(canonicalPath)) {
      continue;
    }

    totalBytes += actualBytes;
    if (totalBytes > MAX_TOTAL_SCAN_BYTES) {
      return {
        valid: false,
        statusCode: 413,
        error: `Total scan payload exceeds maximum limit of ${MAX_TOTAL_SCAN_BYTES / (1024 * 1024)}MB.`,
      };
    }

    pathMap.set(canonicalPath, {
      path: canonicalPath,
      content: file.content,
      sizeBytes: actualBytes,
      language: typeof file.language === 'string' ? file.language : undefined,
    });
  }

  const deduplicatedFiles = Array.from(pathMap.values());

  return {
    valid: true,
    files: deduplicatedFiles,
    targetName: metaValidation.targetName,
    targetType: metaValidation.targetType,
    targetUrl: metaValidation.targetUrl,
  };
}

/**
 * Safely encodes every path segment in a repository-relative path for inclusion in GitHub raw URLs.
 * Preserves directory separators ('/') while encoding spaces, '?', '#', '%', and Unicode characters.
 */
export function encodeRepoPath(pathStr: string): string {
  if (!pathStr || typeof pathStr !== 'string') return '';
  return pathStr
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
}

/**
 * Assigns an integer priority to a file path based on its security significance.
 * Lower numbers denote higher scanning priority.
 */
export function getSecurityPriority(filePath: string): number {
  if (!filePath || typeof filePath !== 'string') return 10;
  const lower = filePath.toLowerCase();
  const segments = lower.split('/');
  const fileName = segments[segments.length - 1] || lower;

  // Rank 1: Environment files (.env, .env.production, etc.)
  if (fileName.startsWith('.env')) return 1;

  // Rank 2: CI / Workflow files
  if (
    lower.includes('.github/workflows/') ||
    lower.includes('.gitlab-ci') ||
    lower.includes('.circleci/') ||
    fileName === 'jenkinsfile' ||
    fileName === 'bitbucket-pipelines.yml'
  ) {
    return 2;
  }

  // Rank 3: Docker & Container definitions
  if (
    fileName === 'dockerfile' ||
    fileName.startsWith('dockerfile.') ||
    fileName.startsWith('docker-compose') ||
    fileName === 'containerfile'
  ) {
    return 3;
  }

  // Rank 4: Dependency manifests
  if (
    fileName === 'package.json' ||
    fileName === 'requirements.txt' ||
    fileName === 'pyproject.toml' ||
    fileName === 'cargo.toml' ||
    fileName === 'go.mod' ||
    fileName === 'gemfile' ||
    fileName === 'composer.json' ||
    fileName === 'pom.xml' ||
    fileName === 'build.gradle'
  ) {
    return 4;
  }

  // Rank 5: Auth, security configs, database setups
  if (
    fileName.includes('auth') ||
    fileName.includes('jwt') ||
    fileName.includes('secret') ||
    fileName.includes('security') ||
    fileName.includes('database') ||
    fileName.includes('credential') ||
    fileName === 'nginx.conf'
  ) {
    return 5;
  }

  // Rank 10: Standard application code
  return 10;
}

/**
 * Orders candidate files so that security-sensitive files (.env*, CI workflows, Dockerfiles,
 * manifests) are prioritized before candidate limits truncate the scan set.
 */
export function prioritizeSecurityFiles<T extends { path: string }>(files: T[]): T[] {
  return [...files].sort((a, b) => {
    const prioA = getSecurityPriority(a.path);
    const prioB = getSecurityPriority(b.path);
    if (prioA !== prioB) {
      return prioA - prioB;
    }
    return a.path.localeCompare(b.path);
  });
}

export interface ValidatedChatPayload {
  messages: Array<{ role: string; content: string }>;
  codeContext?: { currentFile?: string; content?: string };
  activeIssue?: Record<string, any>;
  userQuery: string;
}

/**
 * Validates chat request payloads against strict bounds:
 * - message count <= MAX_CHAT_MESSAGES (20)
 * - per-message length <= MAX_USER_MESSAGE_CHARS (4,000)
 * - total conversation characters <= MAX_TOTAL_CONVERSATION_CHARS (16,000)
 * - code context length <= MAX_CODE_CONTEXT_CHARS (4,000)
 * - active issue size <= MAX_ACTIVE_ISSUE_CHARS (2,000)
 */
export function validateChatPayload(body: unknown): ValidationResult<ValidatedChatPayload> {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false, statusCode: 400, error: 'Chat payload must be a JSON object.' };
  }

  const { messages, codeContext, activeIssue } = body as Record<string, any>;

  if (!messages || !Array.isArray(messages) || messages.length === 0) {
    return { valid: false, statusCode: 400, error: 'Messages array is required and must not be empty.' };
  }

  if (messages.length > MAX_CHAT_MESSAGES) {
    return {
      valid: false,
      statusCode: 400,
      error: `Messages array exceeds maximum allowed count of ${MAX_CHAT_MESSAGES} messages.`,
    };
  }

  let totalChars = 0;
  const validatedMessages: Array<{ role: string; content: string }> = [];

  for (let i = 0; i < messages.length; i++) {
    const m = messages[i];
    if (!m || typeof m !== 'object' || typeof m.content !== 'string' || typeof m.role !== 'string') {
      return {
        valid: false,
        statusCode: 400,
        error: `Message at index ${i} must be an object with valid string role and content.`,
      };
    }

    if (m.content.length > MAX_USER_MESSAGE_CHARS) {
      return {
        valid: false,
        statusCode: 400,
        error: `Message at index ${i} exceeds maximum length of ${MAX_USER_MESSAGE_CHARS} characters.`,
      };
    }

    totalChars += m.content.length;
    validatedMessages.push({ role: m.role, content: m.content });
  }

  if (totalChars > MAX_TOTAL_CONVERSATION_CHARS) {
    return {
      valid: false,
      statusCode: 400,
      error: `Total conversation text (${totalChars} chars) exceeds maximum allowed limit of ${MAX_TOTAL_CONVERSATION_CHARS} characters.`,
    };
  }

  const lastUserMessage = [...validatedMessages].reverse().find((m) => m.role === 'user');
  if (!lastUserMessage || !lastUserMessage.content.trim()) {
    return {
      valid: false,
      statusCode: 400,
      error: 'At least one user message with non-empty content is required.',
    };
  }

  // Validate codeContext
  let validatedCodeContext: { currentFile?: string; content?: string } | undefined;
  if (codeContext !== undefined && codeContext !== null) {
    if (typeof codeContext !== 'object' || Array.isArray(codeContext)) {
      return { valid: false, statusCode: 400, error: 'codeContext must be an object.' };
    }
    const contextContent = typeof codeContext.content === 'string' ? codeContext.content : '';
    if (contextContent.length > MAX_CODE_CONTEXT_CHARS) {
      return {
        valid: false,
        statusCode: 400,
        error: `codeContext content (${contextContent.length} chars) exceeds maximum allowed limit of ${MAX_CODE_CONTEXT_CHARS} characters.`,
      };
    }
    validatedCodeContext = {
      currentFile: typeof codeContext.currentFile === 'string' ? codeContext.currentFile.slice(0, 500) : undefined,
      content: contextContent,
    };
  }

  // Validate activeIssue
  let validatedActiveIssue: Record<string, any> | undefined;
  if (activeIssue !== undefined && activeIssue !== null) {
    if (typeof activeIssue !== 'object' || Array.isArray(activeIssue)) {
      return { valid: false, statusCode: 400, error: 'activeIssue must be an object.' };
    }
    let serialized = '';
    try {
      serialized = JSON.stringify(activeIssue);
    } catch {
      return { valid: false, statusCode: 400, error: 'activeIssue cannot be serialized.' };
    }
    if (serialized.length > MAX_ACTIVE_ISSUE_CHARS) {
      return {
        valid: false,
        statusCode: 400,
        error: `activeIssue size (${serialized.length} chars) exceeds maximum allowed limit of ${MAX_ACTIVE_ISSUE_CHARS} characters.`,
      };
    }
    validatedActiveIssue = activeIssue;
  }

  return {
    valid: true,
    value: {
      messages: validatedMessages,
      codeContext: validatedCodeContext,
      activeIssue: validatedActiveIssue,
      userQuery: lastUserMessage.content,
    },
  };
}

