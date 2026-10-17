import { scryptSync, randomBytes, timingSafeEqual, createHash } from 'node:crypto';

const KEY_LEN = 64;
const SCRYPT_PARAMS = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 } as const;

export function hashPassword(password: string): { hash: string; salt: string } {
  const salt = randomBytes(16).toString('base64');
  const hash = scryptSync(password.normalize('NFKC'), salt, KEY_LEN, SCRYPT_PARAMS).toString('base64');
  return { hash, salt };
}

export function verifyPassword(password: string, hash: string, salt: string): boolean {
  const candidate = scryptSync(password.normalize('NFKC'), salt, KEY_LEN, SCRYPT_PARAMS);
  const expected = Buffer.from(hash, 'base64');
  if (candidate.length !== expected.length) return false;
  return timingSafeEqual(candidate, expected);
}

/**
 * Hash a bearer/refresh token for storage. Tokens are high-entropy random
 * values, so a fast hash is appropriate here — unlike passwords, there is no
 * dictionary to grind against.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('base64');
}

export function generateToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}
