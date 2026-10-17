import type { Request, Response, NextFunction } from 'express';
import { ZodError } from 'zod';
import { env } from '../config/env.js';

export class HttpError extends Error {
  constructor(public status: number, public code: string, message?: string) {
    super(message ?? code);
  }
}

export function notFound(_req: Request, res: Response): void {
  res.status(404).json({ error: 'not_found' });
}

/**
 * Forwards async rejections to the error middleware.
 *
 * Express 4 only catches synchronously thrown errors. Most routes here are
 * synchronous because better-sqlite3 is, but anything awaiting (WebAuthn
 * verification, for one) MUST be wrapped or a thrown HttpError becomes an
 * unhandled rejection and the client is left hanging.
 */
export function asyncRoute<T extends Request = Request>(
  handler: (req: T, res: Response, next: NextFunction) => Promise<unknown>,
) {
  return (req: T, res: Response, next: NextFunction): void => {
    void handler(req, res, next).catch(next);
  };
}

export function errorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _next: NextFunction,
): void {
  if (err instanceof ZodError) {
    res.status(400).json({ error: 'validation_failed', details: err.flatten() });
    return;
  }
  if (err instanceof HttpError) {
    res.status(err.status).json({ error: err.code, message: err.message });
    return;
  }

  console.error('[unhandled]', err);
  res.status(500).json({
    error: 'internal_error',
    // Never leak stack traces or driver messages to clients in production.
    ...(env.isProduction ? {} : { message: err instanceof Error ? err.message : String(err) }),
  });
}
