# Security Policy — Deduplex

## Supported versions

| Version / channel | Supported |
|-------------------|-----------|
| `0.1.0-spike` desktop (`Deduplex-Setup.exe` / `Deduplex.exe`) | Best-effort while the spike is current |
| `main` / unreleased source | Best-effort |

There is no long-term support (LTS) channel yet.

## Reporting a vulnerability

**Do not** open a public GitHub issue for security vulnerabilities.

Please report privately:

1. Email the maintainers (prefer a security contact listed on the repo), **or**
2. Use GitHub **Private vulnerability reporting** on the public `deduplex` repository if that feature is enabled.

Include:

- Deduplex version (`0.1.0-spike`, commit SHA, or Setup build date)
- OS and how you run it (Setup install vs source `uvicorn` / `scripts/desktop_app.py`)
- Steps to reproduce, impact, and any proof-of-concept (keep PoC minimal)
- Whether the issue affects localhost-only bind, auth-off lab mode, import parsers, or exports

You should receive an acknowledgement within a few business days when a contact is live. Do not disclose publicly until a fix or coordinated disclosure window is agreed.

## Scope and product security posture

Deduplex is a **localhost-only desktop / lab** assistant for consolidating scanner results (Nmap XML, Nessus exports). Current spike defaults:

- Desktop launcher **hard-binds `127.0.0.1`** — env attempts to open `0.0.0.0` / `*` are ignored or refused.
- **Auth off** (`AUTH_ENABLED=false`) is acceptable **only** because the bind is localhost.
- Public `/evidence` requires explicit `ALLOW_INSECURE_OPEN_MODE=true` (forced off in the desktop launcher).
- No `.env` is shipped in the Windows bundle; launch strips `SESSION_SECRET` / `BOOTSTRAP_API_KEY` / `API_KEY_PEPPER` from the process environment.
- Writable DB + evidence live under `%LOCALAPPDATA%\Deduplex\` (not next to the exe).

### Out of scope / will be declined as feature requests disguised as vulns

- Asking maintainers to **bind `0.0.0.0` (or all interfaces) without enabling authentication** — we will not document or ship that as a supported lab profile.
- Issues that require intentionally setting `ALLOW_INSECURE_OPEN_MODE=true` in auth-off mode.
- Report findings that are only present when the user pastes **customer evidence / real engagement dumps** into sample paths (treat those as data-handling mistakes, not product CVEs, unless the app exfiltrates them).

### In scope (examples)

- Localhost privilege issues, CSRF/session flaws when auth is enabled, path traversal on uploads/evidence, XXE or unsafe XML handling in importers, secret leakage in logs/exports/installer, unintended network exposure despite the localhost bind.

## Safe lab practice

- Keep the desktop spike on **127.0.0.1**.
- Do **not** expose the UI to a LAN or the internet without `AUTH_ENABLED=true`, a strong `SESSION_SECRET`, and a real `BOOTSTRAP_API_KEY`.
- Never commit `.env`, API keys, or real customer scanner exports.

