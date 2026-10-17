import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';
import { env } from '../config/env.js';
import type { DataKey } from '@oneconscious/shared';

/**
 * Wraps/unwraps a user's data key for REMOTE (server-side decrypting) AI
 * access — see remote_access_grants in db/schema.sql for the property this
 * protects and why it is a deliberate weakening of the E2E guarantee for
 * opted-in accounts only.
 *
 * REMOTE_ACCESS_KEK is a high-entropy generated secret (openssl rand), not a
 * passphrase, so SHA-256 domain separation (not scrypt) is the right cost
 * here — same reasoning as services/passwords.ts's token hashing: there is no
 * dictionary to grind against.
 */

const ALGO = 'aes-256-gcm';
const IV_LEN = 12;

function kekBytes(): Buffer {
  return createHash('sha256').update('oneconscious:remote-access-kek:v1').update(env.REMOTE_ACCESS_KEK).digest();
}

export interface WrappedKey {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

/** Binds the wrapped blob to this user, so it cannot be replayed against a different account's row. */
function aad(userId: number): Buffer {
  return Buffer.from(`remote-access-key|${userId}`);
}

export function wrapDataKey(userId: number, dataKey: DataKey): WrappedKey {
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, kekBytes(), iv);
  cipher.setAAD(aad(userId));
  const ciphertext = Buffer.concat([cipher.update(dataKey), cipher.final()]);
  return { ciphertext, iv, authTag: cipher.getAuthTag() };
}

export function unwrapDataKey(
  userId: number,
  wrapped: { wrapped_data_key: Buffer; wrapped_data_key_iv: Buffer; wrapped_data_key_auth_tag: Buffer },
): DataKey {
  const decipher = createDecipheriv(ALGO, kekBytes(), wrapped.wrapped_data_key_iv);
  decipher.setAAD(aad(userId));
  decipher.setAuthTag(wrapped.wrapped_data_key_auth_tag);
  return Buffer.concat([decipher.update(wrapped.wrapped_data_key), decipher.final()]) as DataKey;
}
