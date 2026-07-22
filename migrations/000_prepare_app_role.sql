\set ON_ERROR_STOP on

BEGIN;

-- app_password_b64 is injected through psql stdin by prepare-app-role.sh.
SELECT format(
  'CREATE ROLE sub2api_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD %L',
  convert_from(decode(:'app_password_b64', 'base64'), 'UTF8')
)
WHERE NOT EXISTS (
  SELECT 1 FROM pg_roles WHERE rolname = 'sub2api_app'
) \gexec

SELECT format(
  'ALTER ROLE sub2api_app WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT PASSWORD %L',
  convert_from(decode(:'app_password_b64', 'base64'), 'UTF8')
) \gexec

ALTER ROLE sub2api_app RESET ALL;

DO $$
DECLARE
  membership RECORD;
BEGIN
  FOR membership IN
    SELECT granted.rolname
    FROM pg_auth_members AS memberships
    JOIN pg_roles AS granted ON granted.oid = memberships.roleid
    JOIN pg_roles AS member ON member.oid = memberships.member
    WHERE member.rolname = 'sub2api_app'
  LOOP
    EXECUTE format('REVOKE %I FROM sub2api_app CASCADE', membership.rolname);
  END LOOP;

  FOR membership IN
    SELECT member.rolname
    FROM pg_auth_members AS memberships
    JOIN pg_roles AS granted ON granted.oid = memberships.roleid
    JOIN pg_roles AS member ON member.oid = memberships.member
    WHERE granted.rolname = 'sub2api_app'
  LOOP
    EXECUTE format('REVOKE sub2api_app FROM %I CASCADE', membership.rolname);
  END LOOP;
END
$$;

COMMIT;

\unset app_password_b64
