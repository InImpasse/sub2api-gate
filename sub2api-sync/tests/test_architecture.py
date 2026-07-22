import pathlib
import unittest


ROOT = pathlib.Path(__file__).parents[2]
NGINX = (ROOT / "nginx" / "sub2api.conf").read_text()
SYNC_LOCATION = (ROOT / "nginx" / "sub2api-sync-location.conf").read_text()
SYNC_SOURCE = (ROOT / "sub2api-sync" / "sub2api_sync.py").read_text()
PRIVACY_MIGRATION = (ROOT / "migrations" / "002_remove_conversation_capture.sql").read_text()
WORKER_PUBLIC = (ROOT / "worker-allow-ip" / "src" / "index.js").read_text()
WORKER_ADMIN = (ROOT / "worker-allow-ip" / "src" / "admin.js").read_text()
COMPOSE = (ROOT / "docker-compose.yml").read_text()
SYNC_USAGE = (ROOT / "sub2api-sync" / "usage_metadata.py").read_text()
SYNC_DOCKERFILE = (ROOT / "sub2api-sync" / "Dockerfile").read_text()
STABLE_UPSTREAM = (
    ROOT / "nginx" / "snippets" / "sub2api-upstream-stable.conf"
).read_text()
DEPLOY_README = (ROOT / "deploy" / "README.md").read_text()
DIRECT_CUTOVER = (ROOT / "deploy" / "install-nginx-direct-v1.py").read_text()


class ArchitectureTests(unittest.TestCase):
    def test_v1_traffic_goes_directly_to_sub2api(self):
        v1_block = NGINX.split("location ^~ /v1/ {", 1)[1].split("}", 1)[0]
        upstream_block = NGINX.split("upstream sub2api_backend {", 1)[1].split("}", 1)[0]
        self.assertIn("sub2api-upstream-active.conf", upstream_block)
        self.assertEqual(STABLE_UPSTREAM.strip(), "server 127.0.0.1:8080;")
        self.assertIn("keepalive 64;", upstream_block)
        self.assertIn("proxy_pass http://sub2api_backend;", v1_block)
        self.assertIn("proxy_buffering off;", v1_block)
        self.assertIn("access_log off;", v1_block)
        self.assertIn("error_log /dev/null crit;", v1_block)
        self.assertNotIn("3021", v1_block)
        self.assertNotIn("mirror", v1_block)
        self.assertIn("proxy_set_header Connection $connection_upgrade;", v1_block)
        self.assertNotIn('Connection "upgrade"', v1_block)

        default_block = NGINX.rsplit("location / {", 1)[1].split("}", 1)[0]
        self.assertIn("proxy_pass http://sub2api_backend;", default_block)

    def test_sync_nginx_has_no_capture_endpoint(self):
        self.assertNotIn("capture", SYNC_LOCATION.lower())

    def test_sync_service_has_no_gateway_or_capture_route(self):
        self.assertNotIn('request_path == "/capture"', SYNC_SOURCE)
        self.assertNotIn("relay_request", SYNC_SOURCE)
        self.assertNotIn("debug_response_body", SYNC_SOURCE)

    def test_privacy_migration_drops_content_columns(self):
        for column in (
            "request_headers", "body_text", "body_preview", "response_preview",
            "debug_response_body",
        ):
            self.assertIn(f"DROP COLUMN IF EXISTS {column}", PRIVACY_MIGRATION)

    def test_usage_log_trigger_removes_content_but_not_usage_metadata(self):
        for column in (
            "prompt", "content", "messages", "input", "output", "payload",
            "request_body", "response_body", "request_headers",
            "response_headers", "body", "request", "response", "completion",
        ):
            self.assertIn(f"'{column}', NULL", PRIVACY_MIGRATION)
        self.assertIn(
            "BEFORE INSERT OR UPDATE ON %s", PRIVACY_MIGRATION
        )
        self.assertIn("'usage_logs', jsonb_build_object(", PRIVACY_MIGRATION)
        self.assertIn("public.conversation_content_policy()", PRIVACY_MIGRATION)
        self.assertNotIn("DROP TABLE usage_logs", PRIVACY_MIGRATION)
        self.assertNotIn("DROP COLUMN IF EXISTS input_tokens", PRIVACY_MIGRATION)

    def test_cloudflare_comments_never_contain_uuid_credentials(self):
        self.assertNotIn("sub2api uuid", WORKER_PUBLIC)
        self.assertNotIn("sub2api uuid", WORKER_ADMIN)

    def test_sync_is_a_non_root_read_only_container_without_docker_socket(self):
        service = COMPOSE.split("  sub2api-sync:\n", 1)[1].split("\n  postgres:\n", 1)[0]
        self.assertIn('127.0.0.1:3021:3021', service)
        self.assertIn("read_only: true", service)
        self.assertIn("PYTHONDONTWRITEBYTECODE=1", service)
        self.assertIn("PYTHONUNBUFFERED=1", service)
        self.assertIn('user: "65532:65532"', service)
        self.assertIn("cap_drop:", service)
        self.assertNotIn("docker.sock", service)
        self.assertNotIn('"docker"', SYNC_SOURCE)
        self.assertEqual(
            SYNC_DOCKERFILE.splitlines()[0],
            "FROM postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15 AS postgres-client",
        )
        self.assertIn(
            "FROM python@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df",
            SYNC_DOCKERFILE,
        )
        self.assertNotRegex(
            SYNC_DOCKERFILE,
            r"\b(?:apk\s+add|apt-get|dnf\s|yum\s)",
        )
        self.assertIn("image: sub2api-gate/sub2api-sync:pg18.4-r1", service)
        self.assertIn("pull_policy: never", service)
        self.assertNotIn("build:", service)
        self.assertFalse((ROOT / "sub2api-sync" / "sub2api-sync.service").exists())
        self.assertFalse((ROOT / "deploy" / "sub2api.env.example").exists())

    def test_sync_uses_redis_nonce_and_exposes_healthz(self):
        self.assertIn('"SET", nonce_key, "1", "NX", "EX"', SYNC_SOURCE)
        self.assertNotIn("NONCES =", SYNC_SOURCE)
        self.assertIn('self.path in ("/health", "/healthz")', SYNC_SOURCE)

    def test_gateway_never_uses_persisted_idempotency_response_bodies(self):
        gateway_sources = "\n".join((SYNC_SOURCE, SYNC_USAGE, WORKER_PUBLIC, WORKER_ADMIN))
        self.assertNotIn("idempotency_records", gateway_sources)
        self.assertNotIn("idempotency_records.response_body", gateway_sources)

    def test_first_direct_v1_cutover_is_documented_and_check_only_by_default(self):
        self.assertIn("install-nginx-direct-v1.py check", DEPLOY_README)
        self.assertIn("install-nginx-direct-v1.py --apply", DEPLOY_README)
        self.assertIn("proxy_pass http://sub2api_backend;", DIRECT_CUTOVER)
        self.assertIn("if not arguments.apply:", DIRECT_CUTOVER)
        self.assertIn("previous Nginx configuration was restored", DIRECT_CUTOVER)


if __name__ == "__main__":
    unittest.main()
