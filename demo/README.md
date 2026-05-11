# Demo

[中文说明见主 README](../README.zh-CN.md) | [See English README](../README.md)

This demo is intentionally backend-free.

Open it locally:

```bash
open demo/index.html
```

Or serve it with any static file server:

```bash
python3 -m http.server 4173
```

Then visit:

- `http://127.0.0.1:4173/demo/`

What it demonstrates:

- a mocked `allow-ip` request form
- a mocked admin user list
- frontend username uniqueness validation
- repository architecture and flow explanations

What it does **not** do:

- no real Cloudflare API calls
- no real Turnstile validation
- no real Sub2API provisioning
- no persistence beyond the browser session
