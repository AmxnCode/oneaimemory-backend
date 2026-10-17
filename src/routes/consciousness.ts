import { Router } from 'express';
import { z } from 'zod';
import { EVENT_TYPES } from '@oneconscious/shared';
import * as events from '../repositories/events.js';
import * as devices from '../repositories/devices.js';
import * as users from '../repositories/users.js';
import * as audit from '../repositories/audit.js';
import { requireIntegration } from '../middleware/auth.js';
import { readLimiter } from '../middleware/rateLimiter.js';
import { asyncRoute } from '../middleware/errorHandler.js';

/**
 * Endpoints consumed by the MCP server.
 *
 * Everything here returns CIPHERTEXT. The server cannot decrypt, so it also
 * cannot filter or search on payload content — that work happens in the local
 * MCP server, which holds the key. This is the direct consequence of the
 * option-(B) architecture chosen in docs/PRD-REVIEW.md #1.
 */
export const consciousnessRouter = Router();

consciousnessRouter.use(readLimiter);

/** Caller-supplied model name. Recorded, never trusted. */
function claimedModel(req: { get(h: string): string | undefined }): string | null {
  return req.get('x-ai-model')?.slice(0, 100) ?? null;
}

const MAX_PAGE = 500;

const querySchema = z.object({
  since: z.string().datetime({ offset: true }).optional(),
  until: z.string().datetime({ offset: true }).optional(),
  types: z
    .string()
    .optional()
    .transform((s) => (s ? s.split(',').map((t) => t.trim()).filter(Boolean) : undefined))
    .refine((arr) => !arr || arr.every((t) => (EVENT_TYPES as readonly string[]).includes(t)), {
      message: `types must be a comma-separated subset of: ${EVENT_TYPES.join(', ')}`,
    }),
  deviceId: z.string().max(255).optional(),
  limit: z.coerce.number().int().positive().max(MAX_PAGE).default(100),
  cursor: z.string().max(200).optional(),
});

consciousnessRouter.get('/events', requireIntegration('activity:read'), asyncRoute(async (req, res) => {
  const q = querySchema.parse(req.query);

  const result = await events.queryEvents({
    userId: req.userId!,
    since: q.since,
    until: q.until,
    types: q.types,
    deviceId: q.deviceId,
    limit: q.limit,
    cursor: q.cursor,
  });

  await audit.record({
    userId: req.userId!,
    action: 'ai_read_activity',
    integrationId: req.integration!.id,
    claimedAiModel: claimedModel(req),
    ipAddress: req.ip,
    userAgent: req.get('user-agent') ?? null,
    details: { returned: result.events.length, since: q.since, types: q.types },
  });

  res.json(result);
}));

/**
 * Metadata-only summary. Safe to compute server-side precisely because it
 * touches no payloads: counts, types, timestamps, device liveness.
 */
consciousnessRouter.get('/summary', requireIntegration('consciousness:summary'), asyncRoute(async (req, res) => {
  const dayAgo = new Date(Date.now() - 86400_000).toISOString();
  const weekAgo = new Date(Date.now() - 7 * 86400_000).toISOString();

  const deviceList = await devices.listDevices(req.userId!);
  const lastSyncTimes = deviceList
    .map((d) => d.last_sync)
    .filter((s): s is string => Boolean(s))
    .sort();

  await audit.record({
    userId: req.userId!,
    action: 'ai_read_summary',
    integrationId: req.integration!.id,
    claimedAiModel: claimedModel(req),
    ipAddress: req.ip,
    userAgent: req.get('user-agent') ?? null,
  });

  const prefs = await users.getPreferences(req.userId!);

  res.json({
    totalEvents: await events.countEvents(req.userId!),
    last24h: await events.eventTypeBreakdown(req.userId!, dayAgo),
    last7d: await events.eventTypeBreakdown(req.userId!, weekAgo),
    lastActivity: lastSyncTimes.at(-1) ?? null,
    deviceCount: deviceList.length,
    activeDevices: deviceList.filter((d) => d.is_active === 1).length,
    // Non-sensitive preference subset, so an AI can localise its answers
    // without needing a user-scoped credential.
    preferences: prefs
      ? { timezone: prefs.timezone, language: prefs.language, collectionEnabled: prefs.collection_enabled === 1 }
      : null,
  });
}));

consciousnessRouter.get('/devices', requireIntegration('devices:read'), asyncRoute(async (req, res) => {
  await audit.record({
    userId: req.userId!,
    action: 'ai_read_devices',
    integrationId: req.integration!.id,
    claimedAiModel: claimedModel(req),
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
