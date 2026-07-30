# Contributing

Thanks for considering a contribution!

## Getting started

1. Fork the repo.
2. Create a feature branch (`git checkout -b feat/my-change`).
3. Make your changes.
4. Run `make fmt vet test lint` and fix any issues.
5. Commit using [conventional commits](https://www.conventionalcommits.org/):
   - `fix:` — bug fix
   - `feat:` — new feature
   - `docs:` — documentation
   - `chore:` — tooling, CI, dependencies
   - `ci:` — workflow changes
6. Push and open a pull request.

## Code style

- Run `golangci-lint run` before pushing.
- Avoid adding external dependencies unless necessary.
- Keep the SSRF/security invariants intact — the code has been audited.

## Pull request checklist

- [ ] Tests pass (`make test`)
- [ ] Lint passes (`make lint`)
- [ ] No new dependencies (or a strong reason for them)
- [ ] Commit messages follow conventional commits
