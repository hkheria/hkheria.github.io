#!/usr/bin/env python3
"""Privacy scan: keeps personal data and secrets out of git.

Scans only the lines being added, so content already in the repo never blocks
a commit. Reports file:line and the rule, never the matched value, so CI logs
stay clean. Python stdlib only.

  python3 tools/privacy_scan.py --staged        pre-commit hook (tools/hooks/pre-commit)
  python3 tools/privacy_scan.py --base <sha>    CI: lines added between <sha> and HEAD
  python3 tools/privacy_scan.py --all           audit every tracked file
  python3 tools/privacy_scan.py --self-test     the scanner's own guardrail tests

False positive: put "privacy-scan: allow" on that line, or exclude the path in
.privacy-scan.json: {"exclude": ["glob", "dir/**"], "allow_emails": ["a@b.c"],
"disable": ["rule"]}. Verification output under tests/verify/ (test plans, bug reports) is
always scanned, even when an exclude covers tests/**: a bug report quotes what the tester
saw. The same file is copied into every hkheria project; keep the copies identical (bump
VERSION on change).
"""
import fnmatch
import json
import os
import re
import subprocess
import sys

VERSION = "2"
ALLOW_MARK = "privacy-scan: allow"
SELF = "tools/privacy_scan.py"
ALWAYS_EXCLUDE = [SELF, ".privacy-scan.json", "package-lock.json", "*.min.js"]
ALWAYS_SCAN = ["tests/verify/**"]   # STANDARDS.md rule 8: bug reports quote real output; no config can exclude them

# Personal mailboxes are on consumer domains; institutional senders (bank alerts,
# noreply addresses) are not personal data and stay allowed.
CONSUMER_DOMAINS = (
    "gmail.com", "googlemail.com", "yahoo.com", "yahoo.co.in", "hotmail.com",
    "outlook.com", "live.com", "icloud.com", "me.com", "proton.me",
    "protonmail.com", "rediffmail.com", "aol.com", "gmx.com", "mail.dk",
)

_NUM = r"\d{1,3}(?:[,. ]\d{2,3})+(?:[.,]\d+)?|\d{4,}(?:[.,]\d+)?"
_PLACEHOLDER = ("fake", "dummy", "test", "example", "sample", "placeholder",
                "xxxx", "changeme", "your_", "your-", "redacted", "<")

RULES = [
    # Identity numbers
    ("pan", re.compile(r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b")),
    ("aadhaar", re.compile(r"(?<![\d-])\b[2-9]\d{3}[ -]\d{4}[ -]\d{4}\b(?![ -]?\d)")),
    ("cpr", re.compile(r"\b(?:0[1-9]|[12]\d|3[01])(?:0[1-9]|1[0-2])\d{2}-\d{4}\b")),
    ("card_number", re.compile(r"\b(?:\d{4}[ -]){3}\d{4}\b")),
    ("iban", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,3})?\b")),
    ("account_number", re.compile(
        r"(?i)\b(?:account|acct|a/c|konto(?:nr)?|reg\.? ?nr|folio|demat|client ?id)\b"
        r"[^\n\d]{0,20}\d[\d -]{5,}\d")),
    # Contact details
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")),
    ("phone", re.compile(r"(?<![\w+])\+(?:45|91)[ -]?\d(?:[ -]?\d){7,9}\b")),
    # Money and health values
    ("amount", re.compile(
        r"(?i)(?:₹|\brs\.?|\binr|\bdkk|\bkr\.?)\s?(?:" + _NUM + r")"
        r"|(?:" + _NUM + r")\s?(?:dkk|inr|kr\b|₹)"
        r"|\b\d+(?:\.\d+)?\s?(?:lakhs?|lacs?|crores?|cr)\b"
        r"|₹\s?\d+(?:\.\d+)?\s?[kKlL]\b")),
    ("weight", re.compile(r"(?i)\b\d{2,3}(?:[.,]\d{1,2})?\s?kg\b")),
    ("body_fat", re.compile(r"(?i)\b\d{1,2}(?:[.,]\d)?\s?%\s?(?:body\s?fat|bf)\b")),
    # Secrets
    ("aws_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    # Key material: a PEM header alone on its line (a real key file) or followed by key data;
    # code that merely mentions the header in a string is not a key.
    ("private_key", re.compile(r"^\s*-----BEGIN [A-Z ]*PRIVATE KEY-----\s*$"
                               r"|-----BEGIN [A-Z ]*PRIVATE KEY-----(?:\\n|\s)+[A-Za-z0-9+/=]{40,}")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{50,})")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b|\bGOCSPX-[A-Za-z0-9_-]{24,}|\bya29\.[0-9A-Za-z_-]{20,}|\b1//0[0-9A-Za-z_-]{30,}")),
    ("slack_token", re.compile(r"\bxox[abpr]-[A-Za-z0-9-]{10,}")),
    ("secret_assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)\b[\"']?\s*[:=]\s*"
        r"[\"']([A-Za-z0-9_\-./+=]{16,})[\"']")),
]

FORBIDDEN_FILES = [
    ".env", ".env.*", "*.pem", "*.p12", "*.pfx", "*.key", "id_rsa*", ".clasprc.json", ".clasp.json",
    "credentials*.json", "client_secret*.json", "token.json", "tokens.json", "*.real.*", "*.pdf",
]
FORBIDDEN_ALLOW = [".env.example"]


def _valid(rule, m, cfg):
    text = m.group(0)
    if rule == "iban":
        return iban_valid(text)
    if rule in TOKEN_RULES:
        return len(set(c for c in text if c.isalnum())) >= 10  # placeholders repeat a few characters
    if rule == "account_number":
        digits = re.search(r"\d[\d -]*\d$", text).group(0)
        return not re.fullmatch(r"\d{4}-\d{2}-\d{2}", digits) and len(set(digits) - set(" -")) > 1
    if rule == "email":
        addr = text.lower()
        if addr in cfg["allow_emails"]:
            return False
        return m.group(1).lower() in CONSUMER_DOMAINS
    if rule == "secret_assignment":
        value = m.group(1)
        if re.fullmatch(r"[A-Z0-9_]+", value):  # a constant's name, e.g. 'KITE_API_KEY'
            return False
        return not any(p in value.lower() for p in _PLACEHOLDER)
    return True


TOKEN_RULES = ("github_token", "anthropic_key", "google_key", "slack_token", "aws_key")


def iban_valid(raw):
    """ISO 13616 mod-97 check, as Sentinel's security probe does."""
    s = raw.replace(" ", "")
    try:
        return int("".join(str(int(c, 36)) for c in s[4:] + s[:4])) % 97 == 1
    except ValueError:
        return False


def scan_line(text, cfg=None):
    """Rule names that match one line (empty when clean or allow-marked)."""
    cfg = cfg or default_config()
    if ALLOW_MARK in text:
        return []
    hits = []
    for rule, rx in RULES:
        if rule in cfg["disable"]:
            continue
        if any(_valid(rule, m, cfg) for m in rx.finditer(text)):
            hits.append(rule)
    return hits


def default_config():
    return {"exclude": [], "allow_emails": [], "disable": []}


def load_config(root):
    cfg = default_config()
    path = os.path.join(root, ".privacy-scan.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for key in cfg:
            cfg[key] = [str(v).lower() if key == "allow_emails" else str(v) for v in data.get(key, [])]
    return cfg


def _match(path, pattern):
    if pattern.endswith("/**"):
        return path == pattern[:-3] or path.startswith(pattern[:-2])
    return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(os.path.basename(path), pattern)


def excluded(path, cfg):
    if any(_match(path, p) for p in ALWAYS_EXCLUDE):
        return True
    if any(_match(path, p) for p in ALWAYS_SCAN):
        return False
    return any(_match(path, p) for p in cfg["exclude"])


def forbidden_file(path):
    name = os.path.basename(path)
    if name in FORBIDDEN_ALLOW:
        return False
    return any(fnmatch.fnmatch(name, p) for p in FORBIDDEN_FILES)


def parse_diff(diff):
    """Yield (path, line_no, text) for every added line of a unified diff."""
    path, line_no = None, 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:]
            path = target[2:] if target.startswith("b/") else None
        elif raw.startswith("@@"):
            m = re.search(r"\+(\d+)", raw)
            line_no = int(m.group(1)) if m else 0
        elif raw.startswith("+") and path:
            yield path, line_no, raw[1:]
            line_no += 1
        elif not raw.startswith("-") and not raw.startswith("\\"):
            line_no += 1


def _git(root, *args):
    return subprocess.run(["git", "-C", root, *args], check=True, capture_output=True,
                          text=True, encoding="utf-8", errors="replace").stdout


def _changed_names(root, diff_args):
    out = _git(root, "diff", "--name-only", "--diff-filter=ACMR", *diff_args)
    return [p for p in out.splitlines() if p]


def scan(root, mode, base=None):
    cfg = load_config(root)
    findings = []
    if mode == "all":
        for path in _git(root, "ls-files").splitlines():
            if forbidden_file(path):
                findings.append((path, 0, "forbidden_file"))
            if excluded(path, cfg):
                continue
            full = os.path.join(root, path)
            try:
                if os.path.getsize(full) > 2_000_000:
                    continue
                with open(full, "rb") as f:
                    data = f.read()
            except OSError:
                continue
            if b"\0" in data:
                continue
            for i, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
                findings += [(path, i, r) for r in scan_line(line, cfg)]
        return findings
    diff_args = ["--cached"] if mode == "staged" else [base, "HEAD"]
    for path in _changed_names(root, diff_args):
        if forbidden_file(path):
            findings.append((path, 0, "forbidden_file"))
    diff = _git(root, "diff", "-U0", "--no-color", "--no-ext-diff", "--diff-filter=ACMR", *diff_args)
    for path, line_no, text in parse_diff(diff):
        if not excluded(path, cfg):
            findings += [(path, line_no, r) for r in scan_line(text, cfg)]
    return findings


def self_test():
    """Guardrail tests: each sample must hit exactly the expected rule (None = clean)."""
    gh = "gh" + "p_" + "A1b2C3d4" * 4 + "Zz9Y"
    pk = "-----BEGIN " + "RSA PRIVATE KEY-----"
    cases = [
        ("PAN ABCPE1234F on file", "pan"),
        ("aadhaar 2345 6789 0123", "aadhaar"),
        ("CPR 010190-1234", "cpr"),
        ("card 4111 1111 1111 1111", "card_number"),
        ("IBAN DK50 0040 0440 1162 43", "iban"),
        ("ref AB12 CDEF GHIJ KLMN 0000", None),
        ("return '-----BEGIN PRIVATE KEY-----\\n' + body", None),
        ("key: 'KITE_API_KEY', secret: 'KITE_API_SECRET',", None),
        ("Zerodha account, CSV fallback (2026-10-18)", None),
        ("folio shapes (`9999999/99`)", None),
        ("token " + "gh" + "p_" + "a" * 36, None),
        ("Account no: 123456789012", "account_number"),
        ("folio 1234567/89", "account_number"),
        ("mail someone.real@gmail.com", "email"),
        ("call +45 12 34 56 78", "phone"),
        ("call +91 98765 43210", "phone"),
        ("savings DKK 21,600 a month", "amount"),
        ("about ₹58K extra", "amount"),
        ("target ₹1 Cr", "amount"),
        ("balance 1,23,456.78 INR", "amount"),
        ("3 lakh in the FD", "amount"),
        ("weighed 76.4 kg today", "weight"),
        ("27% body fat", "body_fat"),
        ("key " + "AKIA" + "ABCDEFGHIJKLMNOP", "aws_key"),
        (pk, "private_key"),
        ("token " + gh, "github_token"),
        ("ANTHROPIC=" + "sk-ant-" + "api03-abcdefghijklmnopqrstuv", "anthropic_key"),
        ("const API_KEY = '" + "q8Zr2LmN0pW4xT6vB9cD" + "'", "secret_assignment"),
        # Clean lines (false-positive guards)
        ("ts 1795172822507 build adc6e50", None),
        ("Merge pull request #27, M0 seam, node@22", None),
        ("import '@types/node'; git@github.com:hkheria/x.git", None),
        ("from:(alerts@hdfcbank.net) newer_than:40d", None),
        ("Co-Authored-By: Claude <noreply@anthropic.com>", None),
        ("foods per 100 g, 2026-11-20, 14:30", None),
        ("Account 2 (savings) and folio numbers", None),
        ("const API_KEY = 'fake-key-for-tests-only'", None),
        ("formatted numbers (1,00,000) are refused", None),
        ("DKK 21,600 privacy-scan: allow", None),
        ("SHA256 9F86D081884C7D659A2FEAA0C55AD015", None),
    ]
    failures = []
    for text, want in cases:
        got = scan_line(text)
        ok = got == ([want] if want else [])
        if not ok:
            failures.append(f"  {text!r}: want {want}, got {got}")
    files = [(".env", True), (".env.example", False), ("docs/statement.pdf", True),
             ("apps-script/src/Code.js", False), (".clasprc.json", True)]
    for path, want in files:
        if forbidden_file(path) != want:
            failures.append(f"  file {path}: want forbidden={want}")
    cfg = dict(default_config(), exclude=["tests/**"])
    paths = [("tests/test_x.py", True), ("tests/verify/bugs/001-x.md", False), ("tests/verify/test-plan.md", False),
             ("tools/privacy_scan.py", True)]
    for path, want in paths:
        if excluded(path, cfg) != want:
            failures.append(f"  path {path}: want excluded={want}")
    diff = "+++ b/a.md\n@@ -1,0 +3,2 @@\n+clean\n+DKK 9,999 here\n"
    if list(parse_diff(diff))[1][:2] != ("a.md", 4):
        failures.append("  parse_diff line numbers")
    if failures:
        print("privacy_scan self-test FAILED:\n" + "\n".join(failures))
        return 1
    print(f"privacy_scan self-test passed ({len(cases) + len(files) + len(paths) + 1} cases, v{VERSION})")
    return 0


def main(argv):
    if "--self-test" in argv:
        return self_test()
    root = _git(os.getcwd(), "rev-parse", "--show-toplevel").strip()
    if "--all" in argv:
        mode, base = "all", None
    elif "--base" in argv:
        i = argv.index("--base")
        mode, base = "base", argv[i + 1]
    else:
        mode, base = "staged", None
    findings = scan(root, mode, base)
    if not findings:
        print("privacy_scan: clean")
        return 0
    for path, line_no, rule in findings:
        print(f"{path}:{line_no}: {rule}")
    print(f"\nprivacy_scan: {len(findings)} finding(s); values are not printed. Remove the data, or for a "
          f"false positive add '{ALLOW_MARK}' to the line or exclude the path in .privacy-scan.json.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
