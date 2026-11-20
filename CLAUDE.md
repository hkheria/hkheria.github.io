# hkheria.github.io

Public site (served by GitHub Pages): home, privacy policy and terms for the Health Dashboard OAuth app.

- This repo is public: never add personal data, health data or credentials.
- Privacy scan: `tools/privacy_scan.py` runs on every PR and push to main (`.github/workflows/privacy.yml`) and as a pre-commit
  hook once `git config core.hooksPath tools/hooks` is set. Fix a finding (or mark a true false positive); never bypass it.
- Every change adds its line to `CHANGELOG.md` under today's date (Added / Changed / Fixed / Removed).
- **Backlog:** deferred features (`BL-F##`) and skipped long-term fixes (`BL-T##`) go to `BACKLOG.md`, each with a
  Revisit trigger. Never delete a row; change its Status.
