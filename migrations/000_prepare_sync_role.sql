\set ON_ERROR_STOP on

BEGIN;

-- sync_password_b64 is injected through psql stdin by prepare-sync-role.sh.
-- The password never appears in this file or the psql process arguments.
SELECT format(
  'CREATE ROLE sub2api_sync LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD %L',
  convert_from(decode(:'sync_password_b64', 'base64'), 'UTF8')
)
WHERE NOT EXISTS (
  SELECT 1 FROM pg_roles WHERE rolname = 'sub2api_sync'
) \gexec

SELECT format(
  'ALTER ROLE sub2api_sync WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD %L',
  convert_from(decode(:'sync_password_b64', 'base64'), 'UTF8')
) \gexec

ALTER ROLE sub2api_sync RESET ALL;

DO $$
DECLARE
  membership RECORD;
BEGIN
  FOR membership IN
    SELECT granted_role.rolname AS role_name
    FROM pg_auth_members
    JOIN pg_roles AS granted_role ON granted_role.oid = pg_auth_members.roleid
    JOIN pg_roles AS member_role ON member_role.oid = pg_auth_members.member
    WHERE member_role.rolname = 'sub2api_sync'
  LOOP
    EXECUTE format(
      'REVOKE %I FROM sub2api_sync CASCADE',
      membership.role_name
    );
  END LOOP;

  FOR membership IN
    SELECT member_role.rolname AS role_name
    FROM pg_auth_members
    JOIN pg_roles AS granted_role ON granted_role.oid = pg_auth_members.roleid
    JOIN pg_roles AS member_role ON member_role.oid = pg_auth_members.member
    WHERE granted_role.rolname = 'sub2api_sync'
  LOOP
    EXECUTE format(
      'REVOKE sub2api_sync FROM %I CASCADE',
      membership.role_name
    );
  END LOOP;
END
$$;

COMMIT;

\unset sync_password_b64
