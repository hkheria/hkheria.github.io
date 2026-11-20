# Changelog

Notable changes to hkheria.github.io (public site), newest first. Each change adds its line here.
This repo is public: never add personal data to any file.

## 2026-11-20
- **Changed:** privacy scanner v2 from Sentinel's `scaffold.py sync`: verification output under `tests/verify/` (test plans, bug reports) is always scanned, even when `.privacy-scan.json` excludes `tests/**` (Sentinel BL-T02) (#5)
- **Added:** standards block in `CLAUDE.md` from Sentinel's `scaffold.py sync` (`sentinel:standards` markers): adds the short form of the standards this file lacked, incl. rules 7 (project class) and 8 (`tests/verify/`); the project's own lines are unchanged (#4)
- **Added:** `BACKLOG.md` for deferred features (`BL-F`) and skipped long-term fixes (`BL-T`), from Sentinel's template (`STANDARDS.md` rule 6); `CLAUDE.md` rule (#3)
- **Added:** privacy scan of added lines on every PR and push to main, and as a pre-commit hook (`tools/privacy_scan.py`, shared by all hkheria projects via Sentinel's scaffold) (#2)

## 2026-10-18
- **Added:** home, privacy policy and terms pages for the Health Dashboard Google OAuth app
