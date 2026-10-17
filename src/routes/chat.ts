import { Router } from 'express';
import { z } from 'zod';
import * as chat from '../repositories/chat.js';
import { requireUser } from '../middleware/auth.js';
import { readLimiter, syncLimiter } from '../middleware/rateLimiter.js';
import { HttpError, asyncRoute } from '../middleware/errorHandler.js';

export const chatRouter = Router();

chatRouter.use(requireUser);

const idParam = z.object({ id: z.coerce.number().int().positive() });

function sessionResponse(s: chat.ChatSessionRow) {
  return { id: s.id, title: s.title, kind: s.kind, createdAt: s.created_at, updatedAt: s.updated_at };
}

function messageResponse(m: chat.ChatMessageRow) {
  return { id: m.id, sessionId: m.session_id, role: m.role, content: m.content, createdAt: m.created_at };
}

chatRouter.get('/sessions', readLimiter, asyncRoute(async (req, res) => {
  const sessions = await chat.listSessions(req.userId!);
  res.json({ sessions: sessions.map(sessionResponse) });
}));

const createSessionBody = z.object({
  title: z.string().trim().min(1).max(255).optional(),
  kind: z.enum(['text', 'voice']).default('text'),
});

chatRouter.post('/sessions', readLimiter, asyncRoute(async (req, res) => {
  const { title, kind } = createSessionBody.parse(req.body ?? {});
  const session = await chat.createSession(req.userId!, title ?? 'New chat', kind);
  res.status(201).json(sessionResponse(session));
}));

chatRouter.get('/sessions/:id', readLimiter, asyncRoute(async (req, res) => {
  const { id } = idParam.parse(req.params);
  const session = await chat.findSession(req.userId!, id);
  if (!session) throw new HttpError(404, 'session_not_found');

  const messages = await chat.listMessages(req.userId!, id);
  res.json({ ...sessionResponse(session), messages: messages.map(messageResponse) });
}));

const renameBody = z.object({ title: z.string().trim().min(1).max(255) });

chatRouter.patch('/sessions/:id', readLimiter, asyncRoute(async (req, res) => {
  const { id } = idParam.parse(req.params);
  const { title } = renameBody.parse(req.body);
  const ok = await chat.renameSession(req.userId!, id, title);
  if (!ok) throw new HttpError(404, 'session_not_found');
  res.json({ ok: true });
}));

chatRouter.delete('/sessions/:id', readLimiter, asyncRoute(async (req, res) => {
  const { id } = idParam.parse(req.params);
  const ok = await chat.deleteSession(req.userId!, id);
  if (!ok) throw new HttpError(404, 'session_not_found');
  res.json({ ok: true });
}));

const addMessageBody = z.object({
  role: z.enum(['user', 'assistant']),
  content: z.string().min(1).max(50_000),
});

chatRouter.post('/sessions/:id/messages', syncLimiter, asyncRoute(async (req, res) => {
  const { id } = idParam.parse(req.params);
  const { role, content } = addMessageBody.parse(req.body);

  const message = await chat.addMessage(req.userId!, id, role, content);
  if (!message) throw new HttpError(404, 'session_not_found');

  res.status(201).json(messageResponse(message));
}));
