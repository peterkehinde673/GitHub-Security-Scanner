import { Response } from 'express';

/**
 * Safely sends an error response without disclosing internal stack traces,
 * file paths, environment variables, or library error details.
 */
export function sendSafeError(
  res: Response,
  statusCode: number,
  publicMessage: string,
  internalError?: unknown
): void {
  if (internalError) {
    const errorDetails =
      internalError instanceof Error
        ? `${internalError.name}: ${internalError.message}`
        : String(internalError);

    // Sanitize log to prevent logging secrets, auth headers, or large bodies
    const sanitizedLog = errorDetails
      .replace(/(?:token|key|secret|password|bearer|auth)\s*[:=]\s*[^\s,]+/gi, '[REDACTED]')
      .substring(0, 500);

    console.error(`[API Error ${statusCode}] ${publicMessage} | Details: ${sanitizedLog}`);
  }

  res.status(statusCode).json({ error: publicMessage });
}
