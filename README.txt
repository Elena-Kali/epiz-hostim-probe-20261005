DISPOSABLE HOSTING COMPATIBILITY PROBE, 2026-10-05.
Synthetic data only. No editor code, disease cards, account credentials or secrets.
Dockerfile: Python 3.12 + Node 22 + locked editor package dependencies.
GET /health: package/runtime status and synthetic local marker checksum.
Optional EPIZ_PROBE_DB_HOST: PostgreSQL SSLRequest and fully verified TLS handshake.
Optional EPIZ_PROBE_DB_SERVER_NAME / EPIZ_PROBE_DB_CA_FILE: official trust settings.
Optional EPIZ_PROBE_DB_CA_BASE64: project CA provided at runtime, not in Git.
Optional EPIZ_PROBE_DB_USER / EPIZ_PROBE_DB_PASSWORD / EPIZ_PROBE_DB_NAME:
existing test database credentials, provided only privately at runtime.
Without credentials the probe never authenticates or runs SQL.
EPIZ_PROBE_MODE: inspect (default), seed, or mutate. seed creates only
epiz_disposable_probe_261005.cards with three fake cards if empty. inspect
only reads; mutate changes fake card 1. All SQL uses sslmode=verify-full.
Public GET endpoints never mutate data or disclose secrets or card bodies.
Sequence: seed once, inspect after restart and redeploy, backup, mutate,
restore through provider panel after authorization, inspect original checksum.
This checks provider storage; it does not accept the actual editor.
HTTP 200 is process liveness, NOT a certificate or compatibility acceptance.
File persistence is inferred only by comparing checksums before/after redeploy.
Stop further database tests if verified TLS has not passed.
Budget: Hostim gift balance only, maximum 500 RUB; no top-up or payment methods.
