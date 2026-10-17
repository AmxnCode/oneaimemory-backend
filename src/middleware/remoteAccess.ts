import type { Request, Response, NextFunction } from 'express';
import type { DataKey } from '@oneconscious/shared';
import * as remoteAccess from '../repositories/remoteAccess.js';
import { unwrapDataKey } from '../services/remoteKek.js';
import { asyncRoute } from './errorHandler.js';

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      /** Unwrapped only for the lifetime of this request — never cached. */
      remoteDataKey?: DataKey;
    }
  }
}

/**
 * Gate for /api/remote/* routes that touch ciphertext: 403s unless the user
 * has explicitly opted into remote access (see routes/remoteAccessRoutes.ts),
 * else unwraps their data key onto req.remoteDataKey for this request only.
 */
export const requireRemoteAccessEnabled = asyncRoute(async (req: Request, res: Response, next: NextFunction) => {
  const grant = await remoteAccess.getGrant(req.userId!);
  if (
    !grant?.enabled ||
    !grant.wrapped_data_key ||
    !grant.wrapped_data_key_iv ||
    !grant.wrapped_data_key_auth_tag
  ) {
    res.status(403).json({ error: 'remote_access_not_enabled' });
    return;
  }
  req.remoteDataKey = unwrapDataKey(req.userId!, {
    wrapped_data_key: grant.wrapped_data_key,
    wrapped_data_key_iv: grant.wrapped_data_key_iv,
    wrapped_data_key_auth_tag: grant.wrapped_data_key_auth_tag,
  });
  next();
});
