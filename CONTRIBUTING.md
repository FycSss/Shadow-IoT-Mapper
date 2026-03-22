# Contributing

Thanks for helping make ShadowIoT better! This project favors **small, safe changes** with clear review notes.

## Workflow

1. Create/activate a virtual environment.
2. Install dev deps: `python -m pip install -e .[dev]`
3. Run checks locally: `python -m ruff check .` and `python -m pytest`
4. Keep PRs focused; avoid unrelated refactors.

## Coding guidelines

- Python 3.9+.
- JSON-first outputs; keep CSV as a convenience layer.
- Rate-limit network activity by default; prefer passive collection where possible.
- Add tests for new logic (even small ones).

## Security

- Only scan networks you are authorized to assess.
- Avoid adding aggressive probes; keep default port lists short and documented.

## Commit messages

Use concise, descriptive messages (e.g., `feat: add passive arp listener`, `docs: add quickstart`).
