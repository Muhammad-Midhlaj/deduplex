# Contributing to Deduplex

Thanks for helping improve Deduplex (analyst effort reduction for Nmap/Nessus consolidate, exact dedupe, retest hooks, and the Windows desktop Setup).

Public repository: **[Muhammad-Midhlaj/deduplex](https://github.com/Muhammad-Midhlaj/deduplex)**. Internal checkout folders may still be named `vapt-effort-reduction`.

## Before you start

1. Read [README.md](README.md), [SECURITY.md](SECURITY.md), and [CHANGELOG.md](CHANGELOG.md).
2. Prefer an issue before a large PR (bug report or feature request templates).
3. This public tree is the **Core** desktop/lab product. **Laya fine-tune / heavy ML (`finetune/`, torch weights, pilot checkpoints) stay private or optional** unless VAPT Core explicitly opens them. Do not assume finetune lands in PRs by default.

## Reporting bugs

- Use the **Bug report** issue template.
- Include OS, Python version (for source runs), Deduplex / Setup version (`0.1.0-spike` or commit), and steps to reproduce.
- Attach **synthetic** sample XML/Nessus only — never customer evidence.

## Security vulnerabilities

Report privately per [SECURITY.md](SECURITY.md). Do not file public issues for exploitable vulns.

## Pull requests

1. Fork the public `deduplex` repo (once published) and branch from `main`.
2. Keep changes focused; separate refactors from behavior changes when practical.
3. Fill out the pull request template.
4. Expect CI / `pytest -q` to pass for touched areas. Add or update tests when you change parsers, grouping, decisions, exports, or retest logic.
5. Do not bind the server to `0.0.0.0` in default docs or desktop code without auth.

### Code style (light touch)

- Python 3.11+; match existing FastAPI / SQLAlchemy patterns in `app/`, `importers/`, `services/`.
- Prefer clear names over cleverness; keep imports and modules consistent with neighbors.
- No drive-by reformatting of unrelated files.
- XML parsing must stay on **defusedxml** (XXE-safe) paths already used by importers.

### Tests

```bash
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -q
```

Desktop packaging changes: follow `packaging/README.md` and the release checklist; do not require torch/laya in the desktop dist.

## What not to put in issues or PRs

- **Secrets** — `.env`, API keys, `SESSION_SECRET`, `BOOTSTRAP_API_KEY`, tokens, cookies.
- **Customer evidence** — real engagement names, client hostnames, production IPs, screenshots of client portals, raw customer Nessus/Nmap dumps.
- **PII** — personal emails, employee names beyond your GitHub handle, phone numbers.
- **Finetune corpora / checkpoints** — analyst label JSONL from real engagements, `.pt` weights, Hub tokens, private pilot notes (keep those in the private Laya track).
- **Generated junk** — `dist/`, `.venv/`, `data/*.db`, `data/evidence/**` uploads (except `.gitkeep`).

## License

By contributing, you agree your contributions are licensed under the **Apache License 2.0** (see `LICENSE`).
