# Perf load fixtures

Dummy Nmap / Nessus XML for **Core** import, grouping, and queue volume tests.

Regenerate (files are gitignored):

```bash
python scripts/generate_perf_fixtures.py --hosts 50
python scripts/seed_perf_load.py --hosts 50
```

Not Laya training labels. Prefer a separate SQLite DB when seeding:

```bash
python scripts/seed_perf_load.py \
  --database-url sqlite:///./data/vapt_perf.db \
  --evidence-dir ./data/evidence_perf \
  --hosts 50
```
