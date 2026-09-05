import { CorsOptions } from 'cors';

/**
 * Generates secure CORS configuration options.
 *
 * In production:
 * - If CORS_ORIGIN is set (comma-separated list), only requests matching an allowed origin (or same-origin without an Origin header) are accepted.
 * - If CORS_ORIGIN is unset, strict same-origin requests are accepted (cross-origin browser requests without an approved origin are rejected).
 *
 * In development:
 * - Reflects standard dev origins or allows local development tools.
 */
export function getCorsOptions(customEnvOrigin?: string): CorsOptions {
  const envOrigin = customEnvOrigin !== undefined ? customEnvOrigin : process.env.CORS_ORIGIN;
  const isProduction = process.env.NODE_ENV === 'production';

  if (!isProduction && !envOrigin) {
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

  return {
    origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
      // Requests without Origin header (same-origin navigation, server-to-server, curl) are permitted
      if (!origin) {
        callback(null, true);
        return;
      }

      if (rawOrigins.includes('*')) {
        callback(null, true);
        return;
      }

      if (rawOrigins.length > 0) {
        if (rawOrigins.includes(origin)) {
          callback(null, true);
        } else {
          callback(new Error(`CORS origin "${origin}" is not allowed by CORS_ORIGIN configuration.`));
        }
        return;
      }

      // Check platform host environment variables (e.g. Render, Cloud Run, public domain)
      const platformOrigins = [
        process.env.RENDER_EXTERNAL_URL,
        process.env.PUBLIC_URL,
      ].filter(Boolean) as string[];

      if (platformOrigins.some((url) => origin === url || origin.startsWith(url))) {
        callback(null, true);
        return;
      }

      // Production without CORS_ORIGIN configured: reject cross-origin requests
      callback(new Error('Cross-origin requests are blocked in production. Configure CORS_ORIGIN to allow external domains.'));
    },
    credentials: true,
  };
}
