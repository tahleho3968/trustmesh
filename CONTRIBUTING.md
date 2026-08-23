# Contributing to TrustMesh

Thank you for helping build open trust infrastructure! This project is
community-driven: implementations are open, standards are open, schemas are open.

## Code of Conduct

By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Getting started

> The codebase is still being scaffolded. Until build instructions land here,
> open an issue if anything in this guide doesn't match reality.

1. **Fork** the repository.
2. **Clone** your fork:
   ```bash
   git clone https://github.com/<your-username>/trustmesh.git
   cd trustmesh
   ```
3. **Create a branch** for your change:
   ```bash
   git checkout -b feat/my-feature
   ```
4. **Make your change**, with tests where applicable.
5. **Commit** using [Conventional Commits](https://www.conventionalcommits.org/):
   ```bash
   git commit -m "feat: add selective disclosure builder"
   ```
6. **Push and open a pull request.** Direct pushes to `main` are blocked —
   all changes arrive via PR review.

## Commit style

We use Conventional Commits so changelogs and releases can be automated:

| Type       | Purpose                          |
|------------|----------------------------------|
| `feat`     | New functionality                |
| `fix`      | Bug fixes                        |
| `docs`     | Documentation only               |
| `refactor` | No behavior change               |
| `test`     | Tests only                       |
| `chore`    | Tooling, CI, metadata            |
| `security` | Security fixes (coordinate privately first — see SECURITY.md) |

## Pull request checklist

- [ ] Conventional-commit title (`feat:`, `fix:`, ...)
- [ ] Tests added or updated for behavior changes
- [ ] Documentation updated where relevant
- [ ] No secrets or personal data committed
- [ ] CI green

## RFCs

Significant architectural changes (new crates, protocol decisions, trust-model
changes) should go through an RFC process once `docs/rfcs/` is established —
or open a `proposal` issue today to start the discussion early.

## Reporting issues

- Bugs → [bug report template](.github/ISSUE_TEMPLATE/bug_report.yml)
- Ideas → [feature request template](.github/ISSUE_TEMPLATE/feature_request.yml)
- Security vulnerabilities → **never** in public issues; see [SECURITY.md](SECURITY.md)

## Licensing

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE).
