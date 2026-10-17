-- Verifies the production Postgres schema behaves as designed.
-- Run against a database with postgres-schema.sql already applied.
-- Any failure raises an exception, so psql -v ON_ERROR_STOP=1 fails the build.

\set ON_ERROR_STOP on

DO $$
DECLARE
  uid          BIGINT;
  in_default   BIGINT;
  copies       BIGINT;
  dropped      INT;
  moved        INT;
  partitions   INT;
BEGIN
  -- Both directions must be provisioned: a device returning from a long
  -- offline stretch carries older timestamps.
  SELECT count(*) INTO partitions
    FROM pg_class c
    JOIN pg_inherits i ON i.inhrelid = c.oid
    JOIN pg_class p ON p.oid = i.inhparent
   WHERE p.relname = 'consciousness_events'
     AND c.relname ~ '^consciousness_events_\d{4}_\d{2}$';
  IF partitions < 8 THEN
    RAISE EXCEPTION 'expected >= 8 month partitions, found %', partitions;
  END IF;

  INSERT INTO users (email, password_hash, password_salt, data_key_salt)
  VALUES ('partition-check@test.local', 'h', 's', 'ks')
  RETURNING id INTO uid;

  -- 100 days of history must all route into real partitions.
  INSERT INTO consciousness_events
    (user_id, event_uuid, device_id, event_type, ciphertext, iv, auth_tag, timestamp)
  SELECT uid, gen_random_uuid(), 'd1', 'browsing', '\x00', '\x01', '\x02',
         now() - (n || ' days')::interval
    FROM generate_series(0, 100) n;

  SELECT count(*) INTO in_default FROM consciousness_events_default;
  IF in_default <> 0 THEN
    RAISE EXCEPTION '% row(s) fell into the default partition; retention would silently skip them', in_default;
  END IF;

  -- Idempotency: a replayed batch must collapse.
  INSERT INTO consciousness_events
    (user_id, event_uuid, device_id, event_type, ciphertext, iv, auth_tag, timestamp)
  VALUES (uid, '11111111-1111-4111-8111-111111111111', 'd1', 'app', '\x00','\x01','\x02', now());
  INSERT INTO consciousness_events
    (user_id, event_uuid, device_id, event_type, ciphertext, iv, auth_tag, timestamp)
  VALUES (uid, '11111111-1111-4111-8111-111111111111', 'd1', 'app', '\x00','\x01','\x02', now())
  ON CONFLICT DO NOTHING;

  SELECT count(*) INTO copies FROM consciousness_events
   WHERE event_uuid = '11111111-1111-4111-8111-111111111111';
  IF copies <> 1 THEN
    RAISE EXCEPTION 'replay produced % copies; sync retries would duplicate', copies;
  END IF;

  -- A row far outside the provisioned range lands in default and must be
  -- recoverable. Creating the partition requires evacuating it first.
  INSERT INTO consciousness_events
    (user_id, event_uuid, device_id, event_type, ciphertext, iv, auth_tag, timestamp)
  VALUES (uid, gen_random_uuid(), 'd1', 'app', '\x00','\x01','\x02', now() - interval '3 years');

  SELECT rescue_default_partition() INTO moved;
  IF moved < 1 THEN
    RAISE EXCEPTION 'rescue_default_partition moved % rows, expected >= 1', moved;
  END IF;

  SELECT count(*) INTO in_default FROM consciousness_events_default;
  IF in_default <> 0 THEN
    RAISE EXCEPTION 'default partition still holds % row(s) after rescue', in_default;
  END IF;

  -- Retention drops whole partitions rather than deleting rows.
  SELECT drop_old_event_partitions(2) INTO dropped;
  IF dropped < 1 THEN
    RAISE EXCEPTION 'drop_old_event_partitions dropped nothing; retention is not working';
  END IF;

  -- Constraint enforcement.
  BEGIN
    INSERT INTO consciousness_events
      (user_id, event_uuid, device_id, event_type, ciphertext, iv, auth_tag, timestamp)
    VALUES (uid, gen_random_uuid(), 'd1', 'keylogger', '\x00','\x01','\x02', now());
    RAISE EXCEPTION 'an invalid event_type was accepted';
  EXCEPTION WHEN check_violation THEN
    NULL; -- expected
  END;

  -- Preferences must be one-per-user.
  INSERT INTO user_preferences (user_id) VALUES (uid);
  BEGIN
    INSERT INTO user_preferences (user_id) VALUES (uid);
    RAISE EXCEPTION 'duplicate user_preferences row was accepted';
  EXCEPTION WHEN unique_violation THEN
    NULL; -- expected
  END;

  -- Deleting the user must cascade to every partition.
  DELETE FROM users WHERE id = uid;
  IF EXISTS (SELECT 1 FROM consciousness_events WHERE user_id = uid) THEN
    RAISE EXCEPTION 'events survived user deletion; GDPR erasure would be incomplete';
  END IF;

  RAISE NOTICE 'partition-check: all assertions passed';
END $$;
