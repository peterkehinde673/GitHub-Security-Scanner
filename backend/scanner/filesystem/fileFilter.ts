export interface FileFilterDecision {
  shouldScan: boolean;
  reason?: string;
  language?: string;
  isManifest?: boolean;
  isConfig?: boolean;
}

const BINARY_EXTENSIONS = new Set([
  'png', 'jpg', 'jpeg', 'gif', 'bmp', 'ico', 'svg', 'webp', 'avif',
  'mp3', 'wav', 'ogg', 'mp4', 'webm', 'mov', 'avi',
  'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
  'zip', 'tar', 'gz', 'bz2', '7z', 'rar', 'iso',
  'exe', 'dll', 'so', 'dylib', 'bin', 'o', 'a', 'class', 'pyc', 'wasm',
  'woff', 'woff2', 'ttf', 'eot', 'otf',
]);

const IGNORED_DIRECTORIES = [
  'node_modules',
  'dist',
  'build',
  'out',
  '.next',
  '.git',
  '.svn',
  'vendor',
  '.gradle',
  '.idea',
  '.vscode',
  'coverage',
  '__pycache__',
];

const EXTENSION_LANGUAGE_MAP: Record<string, string> = {
  js: 'javascript',
  jsx: 'javascript',
  mjs: 'javascript',
  cjs: 'javascript',
  ts: 'typescript',
  tsx: 'typescript',
  py: 'python',
  go: 'go',
  rs: 'rust',
  java: 'java',
  php: 'php',
  rb: 'ruby',
  sh: 'shell',
  bash: 'shell',
  zsh: 'shell',
  yml: 'yaml',
  yaml: 'yaml',
  json: 'json',
  toml: 'toml',
  dockerfile: 'dockerfile',
  sql: 'sql',
  env: 'env',
};

export class FileFilter {
  public static evaluate(filePath: string, content?: string, sizeBytes?: number): FileFilterDecision {
    const normalized = filePath.replace(/\\/g, '/');
    const pathSegments = normalized.split('/');
    const fileName = pathSegments[pathSegments.length - 1];
    const lowerName = fileName.toLowerCase();

    // 1. Directory ignores
    for (const segment of pathSegments) {
      if (IGNORED_DIRECTORIES.includes(segment.toLowerCase())) {
        return { shouldScan: false, reason: `Ignored directory: ${segment}` };
      }
    }

    // 2. File size limit (1MB max per file)
    if (sizeBytes && sizeBytes > 1024 * 1024) {
      return { shouldScan: false, reason: 'File exceeds 1MB limit' };
    }

    // 3. Line count limit if content is provided
    if (content) {
      const lineCount = content.split('\n').length;
      if (lineCount > 10000) {
        return { shouldScan: false, reason: 'File exceeds 10,000 lines limit' };
      }
    }

    // 4. Check extension
    const ext = lowerName.includes('.') ? lowerName.split('.').pop() || '' : '';

    if (BINARY_EXTENSIONS.has(ext)) {
      return { shouldScan: false, reason: `Binary or media extension .${ext}` };
    }

    // 5. Minified and map files
    if (lowerName.endsWith('.min.js') || lowerName.endsWith('.min.css') || lowerName.endsWith('.map')) {
      return { shouldScan: false, reason: 'Generated or minified file' };
    }

    // 6. Manifests & Configs (High Priority Targets)
    const isManifest = [
      'package.json',
      'requirements.txt',
      'pyproject.toml',
      'cargo.toml',
      'go.mod',
      'gemfile',
      'composer.json',
    ].includes(lowerName);

    const isConfig =
      lowerName.startsWith('.env') ||
      lowerName === 'dockerfile' ||
      lowerName.endsWith('.dockerfile') ||
      lowerName.endsWith('.yml') ||
      lowerName.endsWith('.yaml') ||
      lowerName === '.npmrc' ||
      lowerName === 'docker-compose.yml';

    const language = isConfig
      ? 'config'
      : isManifest
      ? 'manifest'
      : EXTENSION_LANGUAGE_MAP[ext] || 'text';

    return {
      shouldScan: true,
      language,
      isManifest,
      isConfig,
    };
  }
}
