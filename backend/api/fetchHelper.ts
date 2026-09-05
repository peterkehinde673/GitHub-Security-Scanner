/**
 * Concurrency runner: processes items with a bounded number of simultaneous workers.
 */
export async function runWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  fn: (item: T) => Promise<R>
): Promise<R[]> {
  if (items.length === 0) return [];
  const limit = Math.max(1, Math.min(concurrency, items.length));
  const results: R[] = new Array(items.length);
  let currentIndex = 0;

  const workers = Array.from({ length: limit }, async () => {
    while (currentIndex < items.length) {
      const idx = currentIndex++;
      results[idx] = await fn(items[idx]);
    }
  });

  await Promise.all(workers);
  return results;
}

export interface SafeFetchOptions {
  timeoutMs: number;
  maxBytes: number;
  headers?: Record<string, string>;
}

export interface SafeFetchResult {
  ok: boolean;
  status: number;
  content?: string;
  sizeBytes?: number;
  error?: string;
}

/**
 * Performs an outbound HTTP fetch with explicit timeout and maximum byte read protection.
 * Automatically cleans up timers and terminates the response stream if size limit is exceeded.
 */
export async function fetchWithTimeoutAndLimit(
  url: string,
  options: SafeFetchOptions
): Promise<SafeFetchResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), options.timeoutMs);

  try {
    const response = await fetch(url, {
      headers: options.headers,
      signal: controller.signal,
    });

    if (!response.ok) {
      return { ok: false, status: response.status };
    }

    // Check Content-Length header early if exposed by upstream server
    const contentLengthHeader = response.headers.get('content-length');
    if (contentLengthHeader) {
      const parsedLength = parseInt(contentLengthHeader, 10);
      if (!isNaN(parsedLength) && parsedLength > options.maxBytes) {
        return {
          ok: false,
          status: 413,
          error: `Content length exceeds maximum limit of ${options.maxBytes} bytes.`,
        };
      }
    }

    // Read response with streaming byte limit protection
    if (response.body && typeof response.body.getReader === 'function') {
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let totalBytes = 0;

      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (value) {
            totalBytes += value.byteLength;
            if (totalBytes > options.maxBytes) {
              await reader.cancel();
              return {
                ok: false,
                status: 413,
                error: `Response payload exceeded maximum allowed size of ${options.maxBytes} bytes.`,
              };
            }
            chunks.push(value);
          }
        }
      } finally {
        reader.releaseLock?.();
      }

      const merged = new Uint8Array(totalBytes);
      let offset = 0;
      for (const chunk of chunks) {
        merged.set(chunk, offset);
        offset += chunk.byteLength;
      }
      const text = new TextDecoder('utf-8').decode(merged);
      return {
        ok: true,
        status: 200,
        content: text,
        sizeBytes: totalBytes,
      };
    } else {
      // Fallback for runtimes where body.getReader is undefined
      const text = await response.text();
      const byteLength = Buffer.byteLength(text, 'utf8');
      if (byteLength > options.maxBytes) {
        return {
          ok: false,
          status: 413,
          error: `Response payload exceeded maximum allowed size of ${options.maxBytes} bytes.`,
        };
      }
      return {
        ok: true,
        status: 200,
        content: text,
        sizeBytes: byteLength,
      };
    }
  } catch (err: any) {
    if (err.name === 'AbortError') {
      return { ok: false, status: 408, error: 'Request timed out.' };
    }
    return { ok: false, status: 500, error: 'Outbound request failed.' };
  } finally {
    clearTimeout(timer);
  }
}
