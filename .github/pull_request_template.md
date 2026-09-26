## Summary

What does this PR change and why?

## Type of change

- [ ] Bug fix
- [ ] Feature
- [ ] Docs / templates
- [ ] Packaging / desktop
- [ ] Tests only
- [ ] Refactor (no behavior change)

## Test plan

- [ ] `pytest -q` (or note which tests were run)
- [ ] Manual lab smoke (import → queue decision → export / retest) if UI or import paths changed
- [ ] Desktop / packaging: followed packaging README smoke notes if `packaging/` or `scripts/desktop_app.py` changed

## Security / scrub

- [ ] No `.env`, secrets, API keys, or real customer evidence
- [ ] No finetune corpora, checkpoints, or `LAYA_LOCAL_CHECKPOINT` weights
- [ ] Does not default-bind `0.0.0.0` or enable open evidence mode without auth
- [ ] Desktop changes still exclude `laya` / `torch` / `transformers` from dist

## Related issues

Closes #
