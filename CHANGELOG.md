# Changelog

All notable changes to **Deduplex** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
(spike tags may use a `-spike` pre-release suffix).

## [Unreleased]

### Added

- Open-source readiness docs drafts: CONTRIBUTING, SECURITY, issue/PR templates (packaging for public `deduplex` repo).

### Changed

- Public product naming centers on **Deduplex** (desktop exe / Setup / LocalAppData); internal folder name may remain `vapt-effort-reduction`.

### Notes

- Laya fine-tune / heavy ML remain **private or optional** for public export unless Core decides otherwise.

## [0.1.0-spike] — 2026-09

Desktop packaging spike for lab machines (Windows).

### Added

- **Deduplex** product shell: one-folder PyInstaller build → `Deduplex.exe`.
- Inno Setup installer → **`Deduplex-Setup.exe`** (`AppVersion` `0.1.0-spike`, publisher **Muhammad Midhlaj**).
- Localhost-only desktop launcher profile: bind **127.0.0.1**, auth off, Laya off, no `.env` in bundle; writable data under `%LOCALAPPDATA%\Deduplex\`.
- Optional one-time migration from legacy `%LOCALAPPDATA%\VAPTEffortReduction\` when Deduplex app data is empty.
- Core lab flows already in tree: Nmap/Nessus import, exact duplicate grouping, analyst queue & decisions, confirmed-only exports, retest compare hooks, synthetic `sample_data/`.

### Security

- Desktop enforces localhost bind; strips session/bootstrap secrets from env at launch; `ALLOW_INSECURE_OPEN_MODE` forced false for `/evidence`.

### Known limits

- Lab / spike quality — not production multi-user auth hardening.
- Code signing and WiX MSI not in this spike.
- Laya/torch intentionally excluded from desktop dist.

[Unreleased]: https://github.com/Muhammad-Midhlaj/deduplex/compare/v0.1.0-spike...HEAD
[0.1.0-spike]: https://github.com/Muhammad-Midhlaj/deduplex/releases/tag/v0.1.0-spike
