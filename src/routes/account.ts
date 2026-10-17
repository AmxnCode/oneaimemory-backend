import { Router } from 'express';
import { z } from 'zod';
import * as integrations from '../repositories/integrations.js';
import { SCOPES } from '../repositories/integrations.js';
import * as users from '../repositories/users.js';
import * as events from '../repositories/events.js';
import * as audit from '../repositories/audit.js';
import { requireUser } from '../middleware/auth.js';
import { HttpError, asyncRoute } from '../middleware/errorHandler.js';

export const accountRouter = Router();
accountRouter.use(requireUser);

// --- Integration tokens (per-credential ACL) -------------------------------

accountRouter.post('/integrations', asyncRoute(async (req, res) => {
  const body = z
    .object({
      label: z.string().min(1).max(120),
      scopes: z.array(z.enum(SCOPES)).min(1),
    })
    .parse(req.body);

  const created = await integrations.createIntegration(req.userId!, body.label, body.scopes);
  await audit.record({
    userId: req.userId!,
    action: 'integration_created',
    integrationId: created.id,
    ipAddress: req.ip,
    details: { label: body.label, scopes: body.scopes },
  });

  res.status(201).json({
    ...created,
    warning: 'Store this token now — it is not retrievable again.',
  });
}));

accountRouter.get('/integrations', asyncRoute(async (req, res) => {
  res.json({ integrations: await integrations.listIntegrations(req.userId!), availableScopes: SCOPES });
}));

accountRouter.delete('/integrations/:id', asyncRoute(async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) throw new HttpError(400, 'invalid_id');
  if (!(await integrations.revokeIntegration(req.userId!, id))) {
    throw new HttpError(404, 'integration_not_found');
  }
  await audit.record({ userId: req.userId!, action: 'integration_revoked', integrationId: id, ipAddress: req.ip });
  res.json({ ok: true });
}));

// --- Preferences -----------------------------------------------------------

accountRouter.get('/preferences', asyncRoute(async (req, res) => {
  res.json({
    preferences: await users.getPreferences(req.userId!),
    blockedPatterns: await users.getBlockedPatterns(req.userId!),
  });
}));

accountRouter.patch('/preferences', asyncRoute(async (req, res) => {
  const body = z
    .object({
      collection_enabled: z.boolean().optional(),
      collect_browsing: z.boolean().optional(),
      collect_searches: z.boolean().optional(),
      collect_youtube: z.boolean().optional(),
      collect_files: z.boolean().optional(),
      collect_code_activity: z.boolean().optional(),
      collect_apps: z.boolean().optional(),
      data_retention_days: z.number().int().min(1).max(730).optional(),
      auto_delete_enabled: z.boolean().optional(),
      timezone: z.string().max(50).optional(),
      language: z.string().max(10).optional(),
      theme: z.enum(['light', 'dark', 'auto']).optional(),
    })
    .parse(req.body);

  await users.updatePreferences(req.userId!, body);
  await audit.record({ userId: req.userId!, action: 'preferences_updated', ipAddress: req.ip, details: body });
  res.json({ preferences: await users.getPreferences(req.userId!) });
}));

// --- Blocklist (synced to devices; enforced on-device) ---------------------

accountRouter.post('/blocklist', asyncRoute(async (req, res) => {
  const body = z
    .object({
      type: z.enum(['domain', 'query_term', 'path_prefix']),
      pattern: z.string().min(1).max(500),
    })
    .parse(req.body);

  await users.addBlockedPattern(req.userId!, body.type, body.pattern);
  res.status(201).json({ blockedPatterns: await users.getBlockedPatterns(req.userId!) });
}));

accountRouter.delete('/blocklist', asyncRoute(async (req, res) => {
  const body = z
    .object({
      type: z.enum(['domain', 'query_term', 'path_prefix']),
      pattern: z.string().min(1).max(500),
    })
    .parse(req.body);

  await users.removeBlockedPattern(req.userId!, body.type, body.pattern);
  res.json({ blockedPatterns: await users.getBlockedPatterns(req.userId!) });
}));

// --- Audit log -------------------------------------------------------------

accountRouter.get('/audit', asyncRoute(async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 100, 500);
  res.json({
    entries: await audit.list(req.userId!, limit),
    note: 'claimedAiModel is self-reported by the caller and is NOT verified. ' +
      'The verifiable identity is integrationId.',
  });
}));

// --- Data control ----------------------------------------------------------

accountRouter.delete('/events', asyncRoute(async (req, res) => {
  const body = z.object({ eventUuids: z.array(z.string().uuid()).max(1000).optional() }).parse(req.body ?? {});

  const deleted = body.eventUuids
    ? await events.deleteEvents(req.userId!, body.eventUuids)
    : await events.deleteAllEvents(req.userId!);

  await audit.record({
    userId: req.userId!,
    action: 'delete_data',
    ipAddress: req.ip,
    details: { deleted, scope: body.eventUuids ? 'selected' : 'all' },
  });

  res.json({ deleted });
}));

/**
 * GDPR Art. 20 export. Events come out still encrypted — the server has no
 * plaintext to give. The desktop app decrypts locally to produce a readable
 * archive.
 */
accountRouter.get('/export', asyncRoute(async (req, res) => {
  const all: unknown[] = [];
  let cursor: string | null | undefined;
  do {
    const page = await events.queryEvents({ userId: req.userId!, limit: 500, cursor: cursor ?? undefined });
    all.push(...page.events);
    cursor = page.nextCursor;
  } while (cursor);

  await audit.record({ userId: req.userId!, action: 'export', ipAddress: req.ip, details: { count: all.length } });

  const user = (await users.findUserById(req.userId!))!;
  res.setHeader('Content-Disposition', 'attachment; filename="oneconscious-export.json"');
  res.json({
    exportedAt: new Date().toISOString(),
    format: 'oneconscious/v1',
    encryption: 'AES-256-GCM, key derived client-side from passphrase + dataKeySalt',
    dataKeySalt: user.data_key_salt,
    preferences: await users.getPreferences(req.userId!),
    blockedPatterns: await users.getBlockedPatterns(req.userId!),
    events: all,
  });
}));
