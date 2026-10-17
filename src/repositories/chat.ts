import { db, usePg } from '../db/index.js';
import { pgQuery } from '../db/postgres.js';

export type ChatKind = 'text' | 'voice';
export type ChatRole = 'user' | 'assistant';

export interface ChatSessionRow {
  id: number;
  user_id: number;
  title: string;
  kind: ChatKind;
  created_at: string;
  updated_at: string;
}

export interface ChatMessageRow {
  id: number;
  session_id: number;
  user_id: number;
  role: ChatRole;
  content: string;
  created_at: string;
}

export async function createSession(userId: number, title: string, kind: ChatKind): Promise<ChatSessionRow> {
  if (usePg) {
    const { rows } = await pgQuery<{ id: number }>(
      `INSERT INTO chat_sessions (user_id, title, kind) VALUES ($1, $2, $3) RETURNING id`,
      [userId, title, kind],
    );
    return (await findSession(userId, rows[0]!.id))!;
  }

  const info = db
    .prepare(`INSERT INTO chat_sessions (user_id, title, kind) VALUES (?, ?, ?)`)
    .run(userId, title, kind);
  return (await findSession(userId, Number(info.lastInsertRowid)))!;
}

export async function listSessions(userId: number): Promise<ChatSessionRow[]> {
  if (usePg) {
    const { rows } = await pgQuery<ChatSessionRow>(
      `SELECT * FROM chat_sessions WHERE user_id = $1 ORDER BY updated_at DESC`,
      [userId],
    );
    return rows;
  }
  return db
    .prepare(`SELECT * FROM chat_sessions WHERE user_id = ? ORDER BY updated_at DESC`)
    .all(userId) as ChatSessionRow[];
}

export async function findSession(userId: number, sessionId: number): Promise<ChatSessionRow | undefined> {
  if (usePg) {
    const { rows } = await pgQuery<ChatSessionRow>(
      `SELECT * FROM chat_sessions WHERE id = $1 AND user_id = $2`,
      [sessionId, userId],
    );
    return rows[0];
  }
  return db.prepare(`SELECT * FROM chat_sessions WHERE id = ? AND user_id = ?`).get(sessionId, userId) as
    | ChatSessionRow
    | undefined;
}

export async function renameSession(userId: number, sessionId: number, title: string): Promise<boolean> {
  if (usePg) {
    const { rowCount } = await pgQuery(
      `UPDATE chat_sessions SET title = $1, updated_at = now() WHERE id = $2 AND user_id = $3`,
      [title, sessionId, userId],
    );
    return rowCount > 0;
  }
  return (
    db
      .prepare(
        `UPDATE chat_sessions SET title = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE id = ? AND user_id = ?`,
      )
      .run(title, sessionId, userId).changes > 0
  );
}

export async function deleteSession(userId: number, sessionId: number): Promise<boolean> {
  if (usePg) {
    const { rowCount } = await pgQuery(`DELETE FROM chat_sessions WHERE id = $1 AND user_id = $2`, [
      sessionId,
      userId,
    ]);
    return rowCount > 0;
  }
  return (
    db.prepare(`DELETE FROM chat_sessions WHERE id = ? AND user_id = ?`).run(sessionId, userId).changes > 0
  );
}

/** Bumps updated_at so the sessions list sorts most-recently-active first. */
async function touchSession(sessionId: number): Promise<void> {
  if (usePg) {
    await pgQuery(`UPDATE chat_sessions SET updated_at = now() WHERE id = $1`, [sessionId]);
    return;
  }
  db.prepare(`UPDATE chat_sessions SET updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id = ?`).run(
    sessionId,
  );
}

/**
 * Ownership is enforced here, not by the caller re-checking findSession:
 * the session_id + user_id pair must both match, so a message can never be
 * appended to (or read from) another user's session even with a guessed id.
 */
export async function addMessage(
  userId: number,
  sessionId: number,
  role: ChatRole,
  content: string,
): Promise<ChatMessageRow | undefined> {
  const session = await findSession(userId, sessionId);
  if (!session) return undefined;

  let row: ChatMessageRow | undefined;
  if (usePg) {
    const { rows } = await pgQuery<{ id: number }>(
      `INSERT INTO chat_messages (session_id, user_id, role, content) VALUES ($1, $2, $3, $4) RETURNING id`,
      [sessionId, userId, role, content],
    );
    row = await findMessage(rows[0]!.id);
  } else {
    const info = db
      .prepare(`INSERT INTO chat_messages (session_id, user_id, role, content) VALUES (?, ?, ?, ?)`)
      .run(sessionId, userId, role, content);
    row = await findMessage(Number(info.lastInsertRowid));
  }

  await touchSession(sessionId);
  return row;
}

async function findMessage(id: number): Promise<ChatMessageRow | undefined> {
  if (usePg) {
    const { rows } = await pgQuery<ChatMessageRow>(`SELECT * FROM chat_messages WHERE id = $1`, [id]);
    return rows[0];
  }
  return db.prepare(`SELECT * FROM chat_messages WHERE id = ?`).get(id) as ChatMessageRow | undefined;
}

export async function listMessages(userId: number, sessionId: number): Promise<ChatMessageRow[]> {
  if (usePg) {
    const { rows } = await pgQuery<ChatMessageRow>(
      `SELECT * FROM chat_messages WHERE session_id = $1 AND user_id = $2 ORDER BY created_at ASC, id ASC`,
      [sessionId, userId],
    );
    return rows;
  }
  return db
    .prepare(
      `SELECT * FROM chat_messages WHERE session_id = ? AND user_id = ? ORDER BY created_at ASC, id ASC`,
    )
    .all(sessionId, userId) as ChatMessageRow[];
}
