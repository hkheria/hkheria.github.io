# hkheria.github.io

Public site (served by GitHub Pages): home, privacy policy and terms for the Health Dashboard OAuth app.

- This repo is public: never add personal data, health data or credentials.
- Privacy scan: `tools/privacy_scan.py` runs on every PR and push to main (`.github/workflows/privacy.yml`) and as a pre-commit
  hook once `git config core.hooksPath tools/hooks` is set. Fix a finding (or mark a true false positive); never bypass it.
- Every change adds its line to `CHANGELOG.md` under today's date (Added / Changed / Fixed / Removed).
- **Backlog:** deferred features (`BL-F##`) and skipped long-term fixes (`BL-T##`) go to `BACKLOG.md`, each with a
  Revisit trigger. Never delete a row; change its Status.

## Project standards (see hkheria/sentinel `STANDARDS.md`)
<!-- sentinel:standards:begin. `tools/scaffold.py sync` rewrites this block; a project line with the same label outside it wins. -->
- **Session name:** at the start of every session, once the task is clear, set the title to
  `Personal site: <session name>` with `set_session_title`.
- **Architecture:** `docs/ARCHITECTURE.md` keeps a system diagram (```mermaid) and a decisions log. A PR that changes
  the architecture (new component, data flow, schedule, external service, or a reversed decision) updates both.
- **Changelog:** every code PR adds its line to `CHANGELOG.md` under today's date (Added / Changed / Fixed / Removed,
  with the PR number), in the same commit: the number is the repo's highest PR/issue number + 1. No personal values in it.
- **Class:** `sentinel.json` `"class"` (personal-local / personal-hosted / agent; default from `type`) sets the required
  checks: security + changelog; hosted adds a health heartbeat that alerts; agent adds performance/quota monitoring and
  an audit log of data changes.
- **Verification:** unit tests in `tests/` run in CI. Milestone verification lives in `tests/verify/` (`test-plan.md`,
  scripts, `bugs/<nnn>-<slug>.md`); `tests/verify/`-only commits get no changelog line.
- **Lean docs:** `docs/ARCHITECTURE.md` stays under ~150 lines; the full decisions log goes to `docs/DECISIONS.md` and
  finished milestones to `docs/MILESTONES.md` once it grows. No pasted code or logs in docs.
- **CI and privacy:** tests run in `.github/workflows/checks.yml` and must pass. `tools/privacy_scan.py` runs on every PR
  and push to main and as a pre-commit hook once `git config core.hooksPath tools/hooks` is set. Fix a finding (or mark
  a true false positive); never bypass it. Secrets live in env vars / Script Properties only; keep `.env.example` current.
<!-- sentinel:standards:end -->
