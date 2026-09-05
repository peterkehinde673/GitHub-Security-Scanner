import { CorsOptions } from 'cors';

/**
 * Normalizes a configured URL or origin string to an exact browser Origin (scheme://host[:port]).
 * Strips any trailing slashes, paths, query parameters, or hashes.
 */
export function normalizeToOrigin(input: string): string | null {
  if (!input) return null;
  const trimmed = input.trim();
  if (!trimmed) return null;
  if (trimmed === '*') return '*';

  try {
    const url = new URL(trimmed);
    return url.origin;
  } catch {
    // If not a standard URL, strip trailing slashes
    return trimmed.replace(/\/+$/, '');
  }
}

/**
 * Generates secure CORS configuration options.
 *
 * In production:
 * - CORS_ORIGIN, RENDER_EXTERNAL_URL, and PUBLIC_URL only authorize an exact browser Origin.
 * - Same-origin and server-to-server requests without an Origin header are preserved.
 * - Wildcard CORS ('*') is never paired with credentials.
 *
 * In development:
 * - Reflects standard dev origins or allows local development tools when CORS_ORIGIN is unset.
 */
export function getCorsOptions(customEnvOrigin?: string): CorsOptions {
  const envOrigin = customEnvOrigin !== undefined ? customEnvOrigin : process.env.CORS_ORIGIN;
  const isProduction = process.env.NODE_ENV === 'production';

  // Platform host environment variables (e.g. Render, Cloud Run, public domain)
  const platformUrls = [
    process.env.RENDER_EXTERNAL_URL,
    process.env.PUBLIC_URL,
  ].filter(Boolean) as string[];

  if (!isProduction && envOrigin === undefined && platformUrls.length === 0) {
    // Development default: permissive for local dev server
    return {
      origin: true,
      credentials: true,
    };
  }

  // Parse comma-separated allowlist
  const rawOrigins = envOrigin
    ? envOrigin
        .split(',')
        .map((o) => o.trim())
        .filter(Boolean)
    : [];

  const hasWildcard = rawOrigins.includes('*');

  // Build exact match set for authorized browser origins
  const allowedExactOrigins = new Set<string>();

  for (const raw of rawOrigins) {
    if (raw !== '*') {
      const normalized = normalizeToOrigin(raw);
      if (normalized) {
        allowedExactOrigins.add(normalized);
      }
    }
  }

  for (const url of platformUrls) {
    const normalized = normalizeToOrigin(url);
    if (normalized && normalized !== '*') {
      allowedExactOrigins.add(normalized);
    }
  }

  return {
    origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
      // Requests without Origin header (same-origin navigation, server-to-server, curl) are permitted
      if (!origin) {
        callback(null, true);
        return;
      }

      // If wildcard is configured, allow requests (without credentials)
      if (hasWildcard) {
        callback(null, true);
        return;
      }

      // Exact match against authorized origins only (no startsWith or prefix/suffix matching)
      if (allowedExactOrigins.has(origin)) {
        callback(null, true);
        return;
      }

      if (allowedExactOrigins.size > 0) {
        callback(new Error(`CORS origin "${origin}" is not allowed. Origin must match an exact authorized domain.`));
        return;
      }

      // Production without CORS_ORIGIN or platform origins configured: reject cross-origin requests
      callback(new Error('Cross-origin requests are blocked in production. Configure CORS_ORIGIN to allow external domains.'));
    },
    // CRITICAL SECURITY: Never allow wildcard CORS with credentials
    credentials: !hasWildcard,
  };
}
