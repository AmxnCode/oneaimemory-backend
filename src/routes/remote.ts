import { Router } from 'express';
import { z } from 'zod';
import {
  EVENT_TYPES,
  decryptEvent,
  DecryptionError,
  deriveInterests,
  deriveProjects,
  topApps,
  activityLevel,
  sanitizeUntrusted,
  type ConsciousnessEvent,
} from '@oneconscious/shared';
import * as events from '../repositories/events.js';
import * as devices from '../repositories/devices.js';
import * as users from '../repositories/users.js';
import * as audit from '../repositories/audit.js';
import { requireIntegration } from '../middleware/auth.js';
import { requireRemoteAccessEnabled } from '../middleware/remoteAccess.js';
import { readLimiter } from '../middleware/rateLimiter.js';
import { asyncRoute } from '../middleware/errorHandler.js';

/**
 * Endpoints for remote-mcp-server (ChatGPT and other remote, OAuth-connected
 * clients). Unlike consciousness.ts, these DECRYPT server-side — that is the
 * entire reason a user has to explicitly opt in (see remoteAccess.ts
 * middleware and db/schema.sql's remote_access_grants comment). Every route
 * that touches payload content requires both `requireIntegration('remote:mcp', ...)`
 * and `requireRemoteAccessEnabled`, so a locally-issued desktop token can
 * never reach decrypted data even if leaked, and a remote token stops working
 * the instant the user disables remote access.
 */
export const remoteRouter = Router();
remoteRouter.use(readLimiter);

/**
 * All event types, ai_session included, are available to remote clients
 * once a user has opted into Remote AI Access (requireRemoteAccessEnabled
 * below) — the same disclosed key-sharing tradeoff already covers every
 * other type here, and ai_session content is redacted client-side at
 * ingest (AiSessionWatcher.pushChunk -> redactEvent), before it is ever
 * encrypted or synced, so this path carries no separate secret-scrubbing
 * gap to design for.
 */
const REMOTE_EXPOSED_TYPES = [...EVENT_TYPES];

function windowToIso(hours: number): string {
  return new Date(Date.now() - hours * 3600_000).toISOString();
}

/** Fetch + decrypt up to `max` events since a cutoff, counting (not throwing on) decrypt failures. */
async function fetchDecrypted(
  userId: number,
  key: Parameters<typeof decryptEvent>[1],
  opts: { since: string; types?: string[]; deviceId?: string; max: number },
): Promise<{ events: ConsciousnessEvent[]; decryptFailures: number }> {
  const out: ConsciousnessEvent[] = [];
  let failures = 0;
  let cursor: string | undefined;

  while (out.length < opts.max) {
    const page = await events.queryEvents({
      userId,
      since: opts.since,
      types: opts.types,
      deviceId: opts.deviceId,
      limit: Math.min(500, opts.max - out.length),
      cursor,
    });
    for (const env of page.events) {
      try {
        out.push(decryptEvent(env, key));
      } catch (err) {
        if (err instanceof DecryptionError) failures++;
        else throw err;
      }
    }
    if (!page.nextCursor) break;
    cursor = page.nextCursor;
  }
  return { events: out, decryptFailures: failures };
}

remoteRouter.get('/whoami', requireIntegration(), asyncRoute(async (req, res) => {
  res.json({ userId: req.userId, integrationId: req.integration!.id, scopes: req.integration!.scopes });
}));

const hoursSchema = (max: number, def: number) => z.coerce.number().int().min(1).max(max).default(def);

remoteRouter.get(
  '/consciousness',
  requireIntegration('remote:mcp', 'consciousness:summary'),
  requireRemoteAccessEnabled,
  asyncRoute(async (req, res) => {
    const hours = hoursSchema(168, 24).parse(req.query.hours);
    const since = windowToIso(hours);

    const [{ events: decrypted, decryptFailures }, deviceList, prefs] = await Promise.all([
      fetchDecrypted(req.userId!, req.remoteDataKey!, { since, types: REMOTE_EXPOSED_TYPES, max: 1000 }),
      devices.listDevices(req.userId!),
      users.getPreferences(req.userId!),
    ]);

    const interests = deriveInterests(decrypted, 10);
    const projects = deriveProjects(decrypted, 5);
    const recentSearches = decrypted
      .filter((e): e is Extract<ConsciousnessEvent, { type: 'search' }> => e.type === 'search')
      .slice(0, 8)
      .map((e) => sanitizeUntrusted(e.payload.query, { maxLength: 120 }));

    const eventMix: Record<string, number> = {};
    for (const e of decrypted) eventMix[e.type] = (eventMix[e.type] ?? 0) + 1;

    await audit.record({
      userId: req.userId!,
      action: 'remote_ai_read_consciousness',
      integrationId: req.integration!.id,
      ipAddress: req.ip,
      userAgent: req.get('user-agent') ?? null,
    });

    res.json({
      windowHours: hours,
      eventCount: decrypted.length,
      activityLevel: activityLevel(decrypted, hours),
      activeDevices: deviceList.filter((d) => d.is_active === 1).length,
      lastActivity: deviceList.map((d) => d.last_sync).filter(Boolean).sort().at(-1) ?? null,
      preferences: prefs
        ? { timezone: prefs.timezone, language: prefs.language, collectionEnabled: prefs.collection_enabled === 1 }
        : null,
      projects,
      interests,
      recentSearches,
      eventMix,
      decryptFailures,
    });
  }),
);

remoteRouter.get(
  '/activity',
  requireIntegration('remote:mcp', 'activity:read'),
  requireRemoteAccessEnabled,
  asyncRoute(async (req, res) => {
    const q = z
      .object({
        hours: hoursSchema(720, 24),
        types: z
          .string()
          .optional()
          .transform((s) => (s ? s.split(',').map((t) => t.trim()).filter(Boolean) : undefined))
          .refine((arr) => !arr || arr.every((t) => (REMOTE_EXPOSED_TYPES as readonly string[]).includes(t)), {
            message: `types must be a comma-separated subset of: ${REMOTE_EXPOSED_TYPES.join(', ')}`,
          }),
        deviceId: z.string().max(255).optional(),
        limit: z.coerce.number().int().min(1).max(200).default(50),
      })
      .parse(req.query);

    const { events: decrypted, decryptFailures } = await fetchDecrypted(req.userId!, req.remoteDataKey!, {
      since: windowToIso(q.hours),
      types: q.types ?? REMOTE_EXPOSED_TYPES,
      deviceId: q.deviceId,
      max: Math.min(q.limit * 2, 1000),
    });

    await audit.record({
      userId: req.userId!,
      action: 'remote_ai_read_activity',
      integrationId: req.integration!.id,
      ipAddress: req.ip,
      userAgent: req.get('user-agent') ?? null,
      details: { returned: Math.min(decrypted.length, q.limit), hours: q.hours, types: q.types },
    });

    res.json({ events: decrypted.slice(0, q.limit), decryptFailures });
  }),
);

remoteRouter.get(
  '/search',
  requireIntegration('remote:mcp', 'activity:search'),
  requireRemoteAccessEnabled,
  asyncRoute(async (req, res) => {
    const q = z
      .object({
        query: z.string().min(1).max(200),
        hours: hoursSchema(8760, 720),
        limit: z.coerce.number().int().min(1).max(100).default(25),
      })
      .parse(req.query);

    const { events: decrypted, decryptFailures } = await fetchDecrypted(req.userId!, req.remoteDataKey!, {
      since: windowToIso(q.hours),
      types: REMOTE_EXPOSED_TYPES,
      max: 2000,
    });

    const terms = q.query.toLowerCase().split(/\s+/).filter(Boolean);
    const scored = decrypted
      .map((ev) => {
        const hay = JSON.stringify(ev.payload).toLowerCase();
        const hits = terms.filter((t) => hay.includes(t)).length;
        return { ev, hits };
      })
      .filter((r) => r.hits > 0)
      .sort((a, b) => b.hits - a.hits || b.ev.timestamp.localeCompare(a.ev.timestamp))
      .slice(0, q.limit);

    await audit.record({
      userId: req.userId!,
      action: 'remote_ai_search_activity',
      integrationId: req.integration!.id,
      ipAddress: req.ip,
      userAgent: req.get('user-agent') ?? null,
      details: { matches: scored.length, searched: decrypted.length },
    });

    res.json({ events: scored.map((r) => r.ev), searched: decrypted.length, decryptFailures });
  }),
);

remoteRouter.get(
  '/interests',
  requireIntegration('remote:mcp', 'activity:read'),
  requireRemoteAccessEnabled,
  asyncRoute(async (req, res) => {
    const q = z
      .object({
        hours: hoursSchema(2160, 168),
        limit: z.coerce.number().int().min(1).max(50).default(20),
      })
      .parse(req.query);

    const { events: decrypted, decryptFailures } = await fetchDecrypted(req.userId!, req.remoteDataKey!, {
      since: windowToIso(q.hours),
      types: REMOTE_EXPOSED_TYPES,
      max: 2000,
    });

    await audit.record({
      userId: req.userId!,
      action: 'remote_ai_read_interests',
      integrationId: req.integration!.id,
      ipAddress: req.ip,
      userAgent: req.get('user-agent') ?? null,
    });

    res.json({
      interests: deriveInterests(decrypted, q.limit),
      topApps: topApps(decrypted),
      eventCount: decrypted.length,
      decryptFailures,
    });
  }),
);

remoteRouter.get('/devices', requireIntegration('remote:mcp', 'devices:read'), asyncRoute(async (req, res) => {
  await audit.record({
    userId: req.userId!,
    action: 'remote_ai_read_devices',
    integrationId: req.integration!.id,
    ipAddress: req.ip,
  });

  const list = await devices.listDevices(req.userId!);
  res.json({
    devices: list.map((d) => ({
      deviceId: d.device_id,
      deviceName: d.device_name,
      deviceType: d.device_type,
      lastSync: d.last_sync,
      active: d.is_active === 1,
    })),
  });
}));
