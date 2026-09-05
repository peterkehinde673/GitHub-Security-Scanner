/**
 * Shannon entropy calculation to determine randomness/information density of a token.
 * Typically, true random secrets (like API keys, base64 strings, hex hashes) have an entropy > 3.2 (hex) or > 4.2 (base64).
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const frequencies: Record<string, number> = {};
  for (let i = 0; i < str.length; i++) {
    const char = str[i];
    frequencies[char] = (frequencies[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;

  for (const char in frequencies) {
    const p = frequencies[char] / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Common placeholder check to avoid false positives on mock tokens and sample strings.
 */
export function isCommonPlaceholder(val: string): boolean {
  if (!val) return true;
  const clean = val.trim();
  const lower = clean.toLowerCase();

  // Obvious placeholders requested by specification
  const directMatches = [
    'redacted',
    '[redacted]',
    'your_api_key',
    'your-api-key',
    'your_secret',
    'your-secret',
    'your_token',
    'your-token',
    'your_key',
    'your-key',
    'example-key',
    'example_key',
    'test-key',
    'test_key',
    'dummy-key',
    'dummy_key',
    'changeme',
    '<api_key>',
    '<your_api_key>',
    '${api_key}',
    '${your_api_key}',
    'process.env.api_key',
    'process.env',
    'os.getenv',
    '12345678',
    '1234567890',
    '00000000',
    'xxxxxxxx',
    'password',
    'secret',
    'null',
    'undefined',
    'false',
    'true',
  ];

  if (directMatches.includes(lower)) {
    return true;
  }

  // Check generic template patterns
  if (lower.startsWith('your_') || lower.startsWith('your-') || lower.startsWith('<your')) {
    return true;
  }
  if (lower.startsWith('replace_me') || lower.startsWith('replace-me') || lower.startsWith('insert_')) {
    return true;
  }
  if (lower === 'dummy' || lower === 'placeholder' || lower === 'example' || lower === 'sample') {
    return true;
  }
  if (lower.startsWith('env.') || lower.startsWith('process.env') || lower.startsWith('os.environ')) {
    return true;
  }

  // Check for repetitive or non-random character sequences (e.g. 'AAAAAAAAAAAAA', '111111111111')
  const uniqueChars = new Set(clean.split('')).size;
  if (clean.length >= 16 && uniqueChars <= 3) {
    return true;
  }

  return false;
}
