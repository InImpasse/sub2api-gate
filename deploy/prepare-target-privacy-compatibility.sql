\set ON_ERROR_STOP on

-- Target-only compatibility for the legacy online snapshot.  It preserves
-- configuration data while removing legacy request-log schema that is outside
-- the reviewed content policy.
DO $$
BEGIN
    IF to_regclass('public.settings') IS NOT NULL
       AND NOT EXISTS (
            SELECT 1
            FROM pg_constraint
            WHERE conrelid = 'public.settings'::regclass
              AND contype = 'u'
              AND conkey = ARRAY[
                  (SELECT attnum
                   FROM pg_attribute
                   WHERE attrelid = 'public.settings'::regclass
                     AND attname = 'key'
                     AND attnum > 0
                     AND NOT attisdropped)
              ]
       ) THEN
        ALTER TABLE public.settings
            ADD CONSTRAINT sub2api_gate_settings_key_unique UNIQUE (key);
    END IF;
END
$$;

DROP TABLE IF EXISTS public.request_logs;

DO $$
DECLARE
    audit_relation regclass := to_regclass('public.audit_logs');
BEGIN
    IF audit_relation IS NOT NULL
       AND EXISTS (
            SELECT 1 FROM pg_attribute
            WHERE attrelid = audit_relation
              AND attname = 'extra'
              AND attnum > 0
              AND NOT attisdropped
       ) THEN
        ALTER TABLE public.audit_logs DROP COLUMN extra;
    END IF;
END
$$;
