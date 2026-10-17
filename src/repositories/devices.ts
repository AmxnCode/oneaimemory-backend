import { db, nowIso, usePg } from '../db/index.js';
import { pgQuery } from '../db/postgres.js';

export interface DeviceRow {
  id: number;
  user_id: number;
  device_id: string;
  device_name: string;
  device_type: string;
  os_version: string | null;
  app_version: string | null;
  last_sync: string | null;
  is_active: number;
  created_at: string;
}

function normalize(row: Record<string, unknown>): DeviceRow {
  return { ...row, is_active: row.is_active ? 1 : 0 } as DeviceRow;
}

export async function upsertDevice(params: {
  userId: number;
  deviceId: string;
  deviceName: string;
  deviceType: string;
  osVersion?: string;
  appVersion?: string;
}): Promise<DeviceRow> {
  if (usePg) {
    await pgQuery(
      `INSERT INTO device_registry (user_id, device_id, device_name, device_type, os_version, app_version)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (device_id) DO UPDATE SET
         device_name = excluded.device_name,
         device_type = excluded.device_type,
         os_version  = excluded.os_version,
         app_version = excluded.app_version,
         is_active   = true`,
      [
        params.userId, params.deviceId, params.deviceName, params.deviceType,
        params.osVersion ?? null, params.appVersion ?? null,
      ],
    );
    return (await findDevice(params.userId, params.deviceId))!;
  }

  db.prepare(
    `INSERT INTO device_registry (user_id, device_id, device_name, device_type, os_version, app_version)
     VALUES (?, ?, ?, ?, ?, ?)
     ON CONFLICT (device_id) DO UPDATE SET
       device_name = excluded.device_name,
       device_type = excluded.device_type,
       os_version  = excluded.os_version,
       app_version = excluded.app_version,
       is_active   = 1`,
  ).run(
    params.userId, params.deviceId, params.deviceName, params.deviceType,
    params.osVersion ?? null, params.appVersion ?? null,
  );
  return (await findDevice(params.userId, params.deviceId))!;
}

export async function findDevice(userId: number, deviceId: string): Promise<DeviceRow | undefined> {
  if (usePg) {
    const { rows } = await pgQuery(
      `SELECT * FROM device_registry WHERE user_id = $1 AND device_id = $2`,
      [userId, deviceId],
    );
    return rows[0] ? normalize(rows[0]) : undefined;
  }
  return db
    .prepare(`SELECT * FROM device_registry WHERE user_id = ? AND device_id = ?`)
    .get(userId, deviceId) as DeviceRow | undefined;
}

/**
 * Lookup ignoring ownership. device_id is globally unique, so registration
 * needs this to distinguish "new device" from "another user's device".
 */
export async function findDeviceAnyUser(deviceId: string): Promise<DeviceRow | undefined> {
  if (usePg) {
    const { rows } = await pgQuery(`SELECT * FROM device_registry WHERE device_id = $1`, [deviceId]);
    return rows[0] ? normalize(rows[0]) : undefined;
  }
  return db.prepare(`SELECT * FROM device_registry WHERE device_id = ?`).get(deviceId) as
    | DeviceRow
    | undefined;
}

export async function listDevices(userId: number): Promise<DeviceRow[]> {
  if (usePg) {
    // NULLS LAST is the Postgres-native way to spell what SQLite gets from
    // "DESC" alone (SQLite already sorts NULLs last on DESC).
    const { rows } = await pgQuery(
      `SELECT * FROM device_registry WHERE user_id = $1 ORDER BY last_sync DESC NULLS LAST`,
      [userId],
    );
    return rows.map(normalize);
  }
  return db
    .prepare(`SELECT * FROM device_registry WHERE user_id = ? ORDER BY last_sync DESC NULLS LAST`)
    .all(userId) as DeviceRow[];
}

export async function touchLastSync(userId: number, deviceId: string): Promise<void> {
  if (usePg) {
    await pgQuery(
      `UPDATE device_registry SET last_sync = now() WHERE user_id = $1 AND device_id = $2`,
      [userId, deviceId],
    );
    return;
  }
  db.prepare(`UPDATE device_registry SET last_sync = ? WHERE user_id = ? AND device_id = ?`).run(
    nowIso(),
    userId,
    deviceId,
  );
}

export async function deactivateDevice(userId: number, deviceId: string): Promise<boolean> {
  if (usePg) {
    const { rowCount } = await pgQuery(
      `UPDATE device_registry SET is_active = false WHERE user_id = $1 AND device_id = $2`,
      [userId, deviceId],
    );
    return rowCount > 0;
  }
  return (
    db
      .prepare(`UPDATE device_registry SET is_active = 0 WHERE user_id = ? AND device_id = ?`)
      .run(userId, deviceId).changes > 0
  );
}
