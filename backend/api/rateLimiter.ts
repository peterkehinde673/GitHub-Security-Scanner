import { Request, Response, NextFunction, RequestHandler } from 'express';

export interface RateLimiterOptions {
  windowMs?: number;
  maxRequests?: number;
  message?: string;
  keyGenerator?: (req: Request) => string;
}

interface ClientRecord {
  count: number;
  resetTime: number;
}

/**
 * Lightweight, in-memory rate limiter designed for single-instance Node.js deployments.
 * Prunes expired entries automatically to prevent memory leaks.
 */
export class InMemoryRateLimiter {
  private clients = new Map<string, ClientRecord>();
  private windowMs: number;
  private maxRequests: number;
  private message: string;
  private keyGenerator: (req: Request) => string;
  private cleanupTimer: NodeJS.Timeout | null = null;

  constructor(options: RateLimiterOptions = {}) {
    const envWindow = process.env.RATE_LIMIT_WINDOW_MS ? parseInt(process.env.RATE_LIMIT_WINDOW_MS, 10) : NaN;
    const envMax = process.env.RATE_LIMIT_MAX_REQUESTS ? parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10) : NaN;

    this.windowMs = !isNaN(envWindow) && envWindow > 0 ? envWindow : options.windowMs || 60000;
    this.maxRequests = !isNaN(envMax) && envMax > 0 ? envMax : options.maxRequests || 60;
    this.message = options.message || 'Too many requests. Please try again later.';

    this.keyGenerator =
      options.keyGenerator ||
      ((req: Request) => {
        // Safe IP extraction without blind trust in arbitrary spoofed headers
        const rawIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
        return String(rawIp).replace(/[^a-zA-Z0-9:._-]/g, '');
      });

    // Cleanup stale entries every 60 seconds
    this.cleanupTimer = setInterval(() => {
      this.prune();
    }, 60000);

    if (this.cleanupTimer && typeof this.cleanupTimer.unref === 'function') {
      this.cleanupTimer.unref();
    }
  }

  public prune(): void {
    const now = Date.now();
    for (const [key, record] of this.clients.entries()) {
      if (now > record.resetTime) {
        this.clients.delete(key);
      }
    }
  }

  public clear(): void {
    this.clients.clear();
  }

  public destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.clear();
  }

  public getMiddleware(): RequestHandler {
    return (req: Request, res: Response, next: NextFunction): void => {
      const key = this.keyGenerator(req);
      const now = Date.now();

      let record = this.clients.get(key);

      if (!record || now > record.resetTime) {
        record = {
          count: 1,
          resetTime: now + this.windowMs,
        };
        this.clients.set(key, record);
        res.setHeader('X-RateLimit-Limit', this.maxRequests);
        res.setHeader('X-RateLimit-Remaining', Math.max(0, this.maxRequests - 1));
        res.setHeader('X-RateLimit-Reset', Math.ceil(record.resetTime / 1000));
        next();
        return;
      }

      record.count += 1;

      res.setHeader('X-RateLimit-Limit', this.maxRequests);
      res.setHeader('X-RateLimit-Remaining', Math.max(0, this.maxRequests - record.count));
      res.setHeader('X-RateLimit-Reset', Math.ceil(record.resetTime / 1000));

      if (record.count > this.maxRequests) {
        const retryAfterSeconds = Math.max(1, Math.ceil((record.resetTime - now) / 1000));
        res.setHeader('Retry-After', retryAfterSeconds);
        res.status(429).json({ error: this.message });
        return;
      }

      next();
    };
  }
}

/**
 * Factory to create rate limiting middleware with specific limits.
 */
export function createRateLimiter(options?: RateLimiterOptions): {
  middleware: RequestHandler;
  limiter: InMemoryRateLimiter;
} {
  const limiter = new InMemoryRateLimiter(options);
  return {
    middleware: limiter.getMiddleware(),
    limiter,
  };
}
