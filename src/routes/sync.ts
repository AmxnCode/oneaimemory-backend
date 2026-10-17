import { Router } from 'express';
import { z } from 'zod';
import { syncRequestSchema } from '@oneconscious/shared';
import * as events from '../repositories/events.js';
import * as devices from '../repositories/devices.js';
import * as users from '../repositories/users.js';
import { requireUser } from '../middleware/auth.js';
import { syncLimiter } from '../middleware/rateLimiter.js';
import { HttpError, asyncRoute } from '../middleware/errorHandler.js';

export const syncRouter = Router();

syncRouter.use(requireUser);

const registerSchema = z.object({
  deviceId: z.string().min(8).max(255),
  deviceName: z.string().min(1).max(255),
  deviceType: z.enum(['mac', 'windows', 'linux', 'android', 'ios']),
  osVersion: z.string().max(100).optional(),
  appVersion: z.string().max(50).optional(),
});

syncRouter.post('/devices/register', asyncRoute(async (req, res) => {
  const body = registerSchema.parse(req.body);

  // device_id is globally unique; refuse to re-home another user's device.
  const conflict = await devices.findDeviceAnyUser(body.deviceId);
  if (conflict && conflict.user_id !== req.userId!) {
    throw new HttpError(409, 'device_id_taken');
  }

  const device = await devices.upsertDevice({ userId: req.userId!, ...body });
  res.status(201).json({
    deviceId: device.device_id,
    deviceName: device.device_name,
    deviceType: device.device_type,
    registeredAt: device.created_at,
  });
}));

syncRouter.get('/devices', asyncRoute(async (req, res) => {
  const list = await devices.listDevices(req.userId!);
  res.json({
    devices: list.map((d) => ({
      deviceId: d.device_id,
      deviceName: d.device_name,
      deviceType: d.device_type,
      osVersion: d.os_version,
      appVersion: d.app_version,
      lastSync: d.last_sync,
      active: d.is_active === 1,
    })),
  });
}));

syncRouter.delete('/devices/:deviceId', asyncRoute(async (req, res) => {
  const ok = await devices.deactivateDevice(req.userId!, req.params.deviceId!);
  if (!ok) throw new HttpError(404, 'device_not_found');
  res.json({ ok: true });
}));

/**
 * Batch upload of encrypted events.
 *
 * The server validates envelope shape and stores ciphertext. It cannot read
 * payloads and does not try. Duplicate eventUuids collapse silently so a
 * device that retries after a timeout is not penalised.
 */
syncRouter.post('/events', syncLimiter, asyncRoute(async (req, res) => {
  const { events: batch } = syncRequestSchema.parse(req.body);

  if (batch.length === 0) {
    res.json({ inserted: 0, duplicates: 0, accepted: 0 });
    return;
  }

  const prefs = await users.getPreferences(req.userId!);
  if (prefs && prefs.collection_enabled === 0) {
    // The user paused collection. Accept-and-discard rather than erroring, so
    // an offline device that hasn't seen the pause yet doesn't spin retrying.
    res.json({ inserted: 0, duplicates: 0, accepted: 0, paused: true });
    return;
  }

  const deviceIds = new Set(batch.map((e) => e.deviceId));
  for (const deviceId of deviceIds) {
    if (!(await devices.findDevice(req.userId!, deviceId))) {
      throw new HttpError(400, 'unknown_device', `Device ${deviceId} is not registered`);
    }
  }

  const result = await events.insertEvents(req.userId!, batch);
  for (const deviceId of deviceIds) await devices.touchLastSync(req.userId!, deviceId);

  res.json({ ...result, accepted: batch.length });
}));

/**
 * The device's own view of its history, for the "what have you recorded about
 * me" screen in the app.
 *
 * Returns ciphertext like the MCP endpoint does — the server has nothing else
 * to give. The desktop app decrypts locally with the key it already holds.
 * Separate from /api/consciousness/events because that route authenticates an
 * integration token, and the app holds a user session instead.
 */
const historySchema = z.object({
  since: z.string().datetime({ offset: true }).optional(),
  types: z
    .string()
    .optional()
    .transform((s) => (s ? s.split(',').map((t) => t.trim()).filter(Boolean) : undefined)),
  deviceId: z.string().max(255).optional(),
  limit: z.coerce.number().int().positive().max(500).default(100),
  cursor: z.string().max(200).optional(),
});

syncRouter.get('/events', asyncRoute(async (req, res) => {
  const q = historySchema.parse(req.query);
  res.json(
    await events.queryEvents({
      userId: req.userId!,
      since: q.since,
      types: q.types,
      deviceId: q.deviceId,
      limit: q.limit,
      cursor: q.cursor,
    }),
  );
}));

syncRouter.get('/status', asyncRoute(async (req, res) => {
  const list = await devices.listDevices(req.userId!);
  res.json({
    totalEvents: await events.countEvents(req.userId!),
    breakdown: await events.eventTypeBreakdown(req.userId!),
    devices: list.map((d) => ({
      deviceId: d.device_id,
      deviceName: d.device_name,
      deviceType: d.device_type,
      lastSync: d.last_sync,
      active: d.is_active === 1,
    })),
  });
}));
