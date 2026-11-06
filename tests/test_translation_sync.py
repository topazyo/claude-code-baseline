#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""claude-code-baseline :: tests/test_translation_sync.py

Fixtures for tests/translation_sync.py, the gate that keeps the Hebrew docs in
step with the English ones. A drift check that never fails is worse than none,
because a green run would be read as "the translation is current", so every
defect class the checker claims to catch is planted here once and must fail.

Each case builds a tiny repository in a temp dir (English doc, Hebrew doc, a
hook source file), runs `check` against it, and asserts pass/fail plus a
substring of the failure message. Usage: python3 tests/test_translation_sync.py
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("translation_sync", HERE / "translation_sync.py")
ts = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ts)

EN = """# Guide

Intro with `install.sh`.

## Part 1 — Basics

Run this:

```bash
echo '{"tool_name":"Bash"}' | bash hook.sh
```

Use `git push --force` never.

## Appendix

- **Hook** — a script.
"""

HE = """<div dir="rtl">

<!-- he-sync: preamble sha256={preamble} -->

# מדריך

<!-- he-note:start -->
הערת מתרגם עם `SOMETHING-ONLY-IN-HEBREW`.
<!-- he-note:end -->

פתיחה עם `install.sh`.

<!-- he-sync: part-1--basics sha256={part1} -->
## חלק 1 — יסודות

<sub>[המקור באנגלית](ONBOARDING.md#part-1--basics)</sub>

הריצו:

<div dir="ltr">

```bash
echo '{"tool_name":"Bash"}' | bash hook.sh
```

</div>

אף פעם לא `git push --force`. ראו [נספח ה'](#ה-הודעות).

<!-- he-sync: appendix sha256={appendix} -->
## נספחים

- **hook** — סקריפט.

<!-- he-only: below -->

### ה. הודעות

<!-- he-decoder:start -->

| הקטע | משמעות |
|---|---|
| `Blocked by test guard:` | נחסם |

<!-- he-decoder:end -->

</div>
"""

README_EN = """# Project

Intro.

## Limits

It does `not` protect.
"""

README_HE = """<div dir="rtl">

<!-- he-sync: limits sha256={limits} -->
## מגבלות

זה `not` מגן.

</div>
"""


def build(root: Path, en: str = EN, he: str | None = None, readme_he: str | None = None,
          hook_src: str = 'echo "Blocked by test guard: $X"\n') -> None:
    (root / "hooks").mkdir(parents=True, exist_ok=True)
    (root / "hooks" / "guard.sh").write_text(hook_src, encoding="utf-8")
    (root / "install.sh").write_text("echo install\n", encoding="utf-8")
    (root / "ONBOARDING.md").write_bytes(en.encode("utf-8"))
    (root / "README.md").write_bytes(README_EN.encode("utf-8"))
    secs, _ = ts.english_sections(ts.read_text(root / "ONBOARDING.md"))
    rsecs, _ = ts.english_sections(README_EN)
    if he is None:
        he = HE
    he = he.replace("{preamble}", ts.section_hash(secs["preamble"])) \
           .replace("{part1}", ts.section_hash(secs["part-1--basics"])) \
           .replace("{appendix}", ts.section_hash(secs["appendix"]))
    (root / "ONBOARDING.he.md").write_bytes(he.encode("utf-8"))
    rhe = (readme_he or README_HE).replace("{limits}", ts.section_hash(rsecs["limits"]))
    (root / "README.he.md").write_bytes(rhe.encode("utf-8"))


def run_check(root: Path) -> tuple[int, str]:
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = ts.cmd_check(root)
    return rc, out.getvalue()


def run_cmd(root: Path, *argv: str) -> int:
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return ts.main(["--root", str(root), *argv])


CASES = []


def case(fn):
    CASES.append(fn)
    return fn


@case
def clean_pair_passes(root):
    build(root)
    rc, out = run_check(root)
    assert rc == 0, out


@case
def english_edit_fails_and_names_the_section(root):
    build(root)
    en = (root / "ONBOARDING.md").read_text(encoding="utf-8").replace("never.", "never, ever.")
    (root / "ONBOARDING.md").write_bytes(en.encode("utf-8"))
    rc, out = run_check(root)
    assert rc == 1 and "section 'part-1--basics': the English text changed" in out, out
    assert "preamble" not in out, "an unrelated section was reported:\n" + out


@case
def mark_stale_passes_with_visible_banner_then_stamp_removes_it(root):
    build(root)
    en = (root / "ONBOARDING.md").read_text(encoding="utf-8").replace("never.", "never, ever.")
    (root / "ONBOARDING.md").write_bytes(en.encode("utf-8"))
    assert run_cmd(root, "mark-stale", "ONBOARDING.he.md", "part-1--basics") == 0
    he = (root / "ONBOARDING.he.md").read_text(encoding="utf-8")
    assert ts.STALE_MARK in he and "ייתכן שהסעיף הזה לא מעודכן" in he, he
    rc, out = run_check(root)
    assert rc == 0 and "possibly outdated" in out and "part-1--basics" in out, out
    assert run_cmd(root, "stamp", "ONBOARDING.he.md", "part-1--basics") == 0
    he = (root / "ONBOARDING.he.md").read_text(encoding="utf-8")
    assert ts.STALE_MARK not in he and "ייתכן" not in he, he
    rc, out = run_check(root)
    assert rc == 0 and "possibly outdated" not in out, out


@case
def altered_command_block_fails(root):
    build(root, he=HE.replace("| bash hook.sh\n```", "| bash other.sh\n```"))
    rc, out = run_check(root)
    assert rc == 1 and "bash block missing or altered" in out and "not in the English" in out, out


@case
def dropped_inline_command_fails(root):
    build(root, he=HE.replace("`git push --force`", "push בכוח"))
    rc, out = run_check(root)
    assert rc == 1 and "inline code missing in Hebrew: `git push --force`" in out, out


@case
def invented_inline_command_fails(root):
    build(root, he=HE.replace("`git push --force`", "`git push --force` או `rm -rf /`"))
    rc, out = run_check(root)
    assert rc == 1 and "Hebrew inline code not found in the English: `rm -rf /`" in out, out


@case
def he_note_region_is_not_compared(root):
    build(root)  # the fixture's he-note holds a span the English lacks
    rc, out = run_check(root)
    assert rc == 0 and "SOMETHING-ONLY-IN-HEBREW" not in out, out


@case
def bidi_control_character_fails(root):
    build(root, he=HE.replace("`git push --force`", "`git push ‮--force`"))
    rc, out = run_check(root)
    assert rc == 1 and "bidirectional-control characters" in out, out


@case
def missing_ltr_wrapper_fails(root):
    build(root, he=HE.replace('<div dir="ltr">\n\n```bash', "```bash"))
    rc, out = run_check(root)
    assert rc == 1 and "not wrapped in <div dir=\"ltr\">" in out, out


@case
def missing_rtl_wrapper_fails(root):
    build(root, he=HE.replace('<div dir="rtl">\n', "", 1))
    rc, out = run_check(root)
    assert rc == 1 and 'first line must be <div dir="rtl">' in out, out


@case
def broken_anchor_fails(root):
    build(root, he=HE.replace("ONBOARDING.md#part-1--basics", "ONBOARDING.md#part-1-basics"))
    rc, out = run_check(root)
    assert rc == 1 and "anchor not found in ONBOARDING.md: #part-1-basics" in out, out


@case
def broken_local_anchor_fails(root):
    build(root, he=HE.replace("(#ה-הודעות)", "(#ה-הודעה)"))
    rc, out = run_check(root)
    assert rc == 1 and "anchor not found in this file" in out, out


@case
def decoder_message_gone_from_source_fails(root):
    build(root, hook_src='echo "Refused by test guard: $X"\n')
    rc, out = run_check(root)
    assert rc == 1 and "decoder message no longer in the hook source" in out, out


@case
def untranslated_english_section_fails(root):
    en = EN.replace("## Appendix", "## New part\n\nNew text.\n\n## Appendix")
    build(root, en=en)
    rc, out = run_check(root)
    assert rc == 1 and "English section 'new-part' has no Hebrew translation marker" in out, out


@case
def renamed_english_heading_fails(root):
    build(root)
    en = (root / "ONBOARDING.md").read_text(encoding="utf-8").replace("Part 1 — Basics", "Part 1 — Basic")
    (root / "ONBOARDING.md").write_bytes(en.encode("utf-8"))
    rc, out = run_check(root)
    assert rc == 1 and "marker 'part-1--basics': no such English section" in out, out


@case
def crlf_and_bom_hash_the_same_as_lf(root):
    build(root)
    lf = (root / "ONBOARDING.md").read_bytes()
    (root / "ONBOARDING.md").write_bytes(b"\xef\xbb\xbf" + lf.replace(b"\n", b"\r\n"))
    rc, out = run_check(root)
    assert rc == 0, "a Windows checkout (CRLF/BOM) must not read as drift:\n" + out


@case
def readme_partial_translation_is_allowed(root):
    build(root)  # README.he.md translates only the "Limits" section, and that is fine
    rc, out = run_check(root)
    assert rc == 0, out


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    failed = 0
    for fn in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                fn(Path(tmp))
                print(f"   ok {fn.__name__}")
            except Exception as exc:  # an exception is a failure too, never a skip
                failed += 1
                print(f"  FAIL {fn.__name__}: {type(exc).__name__}: {exc}")
    print(f"   {len(CASES) - failed}/{len(CASES)} translation-sync fixtures passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
