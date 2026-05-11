# Sub2API allow-ip Worker

This directory contains the Cloudflare Worker used for:

- the public `allow-ip` page
- the admin panel
- UUID-based access management
- Cloudflare Rules List writes
- syncing UUID users to the origin-side Sub2API provisioning service

Use the root documentation for the full deployment guide:

- Chinese: [../README.zh-CN.md](../README.zh-CN.md)
- English: [../README.md](../README.md)

## Quick Worker Notes

- `wrangler.jsonc` in this repository is a template and contains placeholder values
- set real secrets with `wrangler secret put ...`
- do not commit real account IDs, KV IDs, or Turnstile secrets

Basic deploy flow:

```bash
cd worker-allow-ip
npm install
npx wrangler deploy
```
