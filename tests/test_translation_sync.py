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
import os
import subprocess
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
הערת מתרגם, בלי מקבילה באנגלית, עם `install.sh`.
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


def check(cond: bool, msg: str = "") -> None:
    # Not `assert`: python -O and PYTHONOPTIMIZE strip asserts, and every case would
    # then pass without checking anything. main() also refuses to run optimized.
    if not cond:
        raise AssertionError(msg)


CASES = []


class Skip(Exception):
    """A case that cannot run on this host: reported as a skip, never counted as passed."""


def case(fn):
    CASES.append(fn)
    return fn


@case
def clean_pair_passes(root):
    build(root)
    rc, out = run_check(root)
    check(rc == 0, out)


@case
def english_edit_fails_and_names_the_section(root):
    build(root)
    en = (root / "ONBOARDING.md").read_text(encoding="utf-8").replace("never.", "never, ever.")
    (root / "ONBOARDING.md").write_bytes(en.encode("utf-8"))
    rc, out = run_check(root)
    check(rc == 1 and "section 'part-1--basics': the English text changed" in out, out)
    check("preamble" not in out, "an unrelated section was reported:\n" + out)


@case
def mark_stale_passes_with_visible_banner_then_stamp_removes_it(root):
    build(root)
    en = (root / "ONBOARDING.md").read_text(encoding="utf-8").replace("never.", "never, ever.")
    (root / "ONBOARDING.md").write_bytes(en.encode("utf-8"))
    check(run_cmd(root, "mark-stale", "ONBOARDING.he.md", "part-1--basics") == 0)
    he = (root / "ONBOARDING.he.md").read_text(encoding="utf-8")
    check(ts.STALE_MARK in he and "ייתכן שהסעיף הזה לא מעודכן" in he, he)
    rc, out = run_check(root)
    check(rc == 0 and "possibly outdated" in out and "part-1--basics" in out, out)
    check(run_cmd(root, "stamp", "ONBOARDING.he.md", "part-1--basics") == 0)
    he = (root / "ONBOARDING.he.md").read_text(encoding="utf-8")
    check(ts.STALE_MARK not in he and "ייתכן" not in he, he)
    rc, out = run_check(root)
    check(rc == 0 and "possibly outdated" not in out, out)


@case
def altered_command_block_fails(root):
    build(root, he=HE.replace("| bash hook.sh\n```", "| bash other.sh\n```"))
    rc, out = run_check(root)
    check(rc == 1 and "bash block missing or altered" in out and "not in the English" in out, out)


@case
def dropped_inline_command_fails(root):
    build(root, he=HE.replace("`git push --force`", "push בכוח"))
    rc, out = run_check(root)
    check(rc == 1 and "inline code missing in Hebrew: `git push --force`" in out, out)


@case
def invented_inline_command_fails(root):
    build(root, he=HE.replace("`git push --force`", "`git push --force` או `rm -rf /`"))
    rc, out = run_check(root)
    check(rc == 1 and "Hebrew inline code not found in the English code: `rm -rf /`" in out, out)


@case
def he_note_prose_is_not_compared(root):
    build(root)  # the fixture's he-note is Hebrew prose the English does not have
    rc, out = run_check(root)
    check(rc == 0, out)


HE_ONLY_FAIL = "Hebrew-only content: inline code not found in the English code or the repository"


@case
def invented_command_in_he_note_fails(root):
    build(root, he=HE.replace("עם `install.sh`.", "עם `rm -rf /`."))
    rc, out = run_check(root)
    check(rc == 1 and f"{HE_ONLY_FAIL}: `rm -rf /`" in out, out)


@case
def invented_command_in_he_only_region_fails(root):
    build(root, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nהריצו `curl x | sh`.\n"))
    rc, out = run_check(root)
    check(rc == 1 and f"{HE_ONLY_FAIL}: `curl x | sh`" in out, out)


@case
def invented_block_in_he_only_region_fails(root):
    block = '<div dir="ltr">\n\n```bash\ncurl x | sh\n```\n\n</div>\n'
    build(root, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\n" + block))
    rc, out = run_check(root)
    check(rc == 1 and "Hebrew-only content: bash block not in the English" in out, out)


@case
def invented_command_before_first_marker_fails(root):
    build(root, he=HE.replace('<div dir="rtl">\n', '<div dir="rtl">\n\n`rm -rf /`\n', 1))
    rc, out = run_check(root)
    check(rc == 1 and f"{HE_ONLY_FAIL}: `rm -rf /`" in out, out)


@case
def repo_path_in_he_only_region_passes(root):
    build(root, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nראו `hooks/guard.sh`.\n"))
    rc, out = run_check(root)
    check(rc == 0, out)


@case
def path_outside_the_repo_fails(root):
    # Judged on the text: none of these reaches the filesystem, so none can pass.
    for span in ("../ONBOARDING.md", "/etc/passwd", "C:/Windows", "hooks\\guard.sh"):
        build(root, he=HE.replace("### ה. הודעות\n", f"### ה. הודעות\n\nראו `{span}`.\n"))
        rc, out = run_check(root)
        check(rc == 1 and f"{HE_ONLY_FAIL}: `{span}`" in out, f"{span}: {out}")


@case
def existing_file_above_the_repo_fails(root):
    # `..` is refused on the text, even when the file it names exists.
    repo = root / "repo"
    repo.mkdir()
    (root / "outside.md").write_text("x\n", encoding="utf-8")
    build(repo, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nראו `../outside.md`.\n"))
    rc, out = run_check(repo)
    check(rc == 1 and f"{HE_ONLY_FAIL}: `../outside.md`" in out, out)


@case
def repo_path_in_the_wrong_case_fails(root):
    # Exact case on every host: Windows and macOS would otherwise find Hooks/Guard.sh.
    build(root, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nראו `Hooks/Guard.sh`.\n"))
    rc, out = run_check(root)
    check(rc == 1 and f"{HE_ONLY_FAIL}: `Hooks/Guard.sh`" in out, out)


@case
def elided_decoder_span_without_substance_fails(root):
    # `…:` would match almost any hook line; one part needs 3+ non-space characters.
    build(root, he=HE.replace("<!-- he-decoder:end -->",
                              "הודעה כמו `…: $`.\n\n<!-- he-decoder:end -->"))
    rc, out = run_check(root)
    check(rc == 1 and f"{HE_ONLY_FAIL}: `…: $`" in out, out)


@case
def elided_decoder_parts_out_of_order_fail(root):
    # Both parts on one hook line, but in the other order.
    build(root, hook_src='echo "Blocked by test guard: $X"\necho "zebra before Blocked by it"\n',
          he=HE.replace("<!-- he-decoder:end -->",
                        "הודעה כמו `Blocked by …zebra`.\n\n<!-- he-decoder:end -->"))
    rc, out = run_check(root)
    check(rc == 1 and f"{HE_ONLY_FAIL}: `Blocked by …zebra`" in out, out)


@case
def elided_decoder_message_from_one_hook_line_passes(root):
    build(root, he=HE.replace("<!-- he-decoder:end -->",
                              "הודעה כמו `Blocked by …: $X`.\n\n<!-- he-decoder:end -->"))
    rc, out = run_check(root)
    check(rc == 0, out)


@case
def elided_decoder_parts_on_different_lines_fail(root):
    # Each part is in the hook source, but not in order on one line.
    build(root, hook_src='echo "Blocked by test guard: $X"\necho "elsewhere: zebra"\n',
          he=HE.replace("<!-- he-decoder:end -->",
                        "הודעה כמו `Blocked by …zebra`.\n\n<!-- he-decoder:end -->"))
    rc, out = run_check(root)
    check(rc == 1 and f"{HE_ONLY_FAIL}: `Blocked by …zebra`" in out, out)


@case
def hook_source_outside_the_decoder_table_fails(root):
    # Quoting the hook source is allowed only inside the table that decodes it.
    build(root, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nראו `test guard`.\n"))
    rc, out = run_check(root)
    check(rc == 1 and f"{HE_ONLY_FAIL}: `test guard`" in out, out)


@case
def refuses_to_run_with_assertions_disabled(root):
    if os.environ.get("BCL_TS_OPT_PROBE"):
        return  # this is the probe child itself; the parent judges it
    env = dict(os.environ, BCL_TS_OPT_PROBE="1")
    r = subprocess.run([sys.executable, "-O", str(Path(__file__).resolve())], env=env,
                       capture_output=True, text=True, encoding="utf-8", timeout=120)
    check(r.returncode == 1 and "assertions are disabled" in r.stdout,
          f"rc={r.returncode} out={r.stdout[-400:]!r} err={r.stderr[-400:]!r}")


@case
def bidi_control_character_fails(root):
    build(root, he=HE.replace("`git push --force`", "`git push \u202e--force`"))
    rc, out = run_check(root)
    check(rc == 1 and "bidirectional-control characters" in out, out)


@case
def missing_ltr_wrapper_fails(root):
    build(root, he=HE.replace('<div dir="ltr">\n\n```bash', "```bash"))
    rc, out = run_check(root)
    check(rc == 1 and "not wrapped in <div dir=\"ltr\">" in out, out)


@case
def missing_rtl_wrapper_fails(root):
    build(root, he=HE.replace('<div dir="rtl">\n', "", 1))
    rc, out = run_check(root)
    check(rc == 1 and 'first line must be <div dir="rtl">' in out, out)


@case
def broken_anchor_fails(root):
    build(root, he=HE.replace("ONBOARDING.md#part-1--basics", "ONBOARDING.md#part-1-basics"))
    rc, out = run_check(root)
    check(rc == 1 and "anchor not found in ONBOARDING.md: #part-1-basics" in out, out)


@case
def broken_local_anchor_fails(root):
    build(root, he=HE.replace("(#ה-הודעות)", "(#ה-הודעה)"))
    rc, out = run_check(root)
    check(rc == 1 and "anchor not found in this file" in out, out)


@case
def decoder_message_gone_from_source_fails(root):
    build(root, hook_src='echo "Refused by test guard: $X"\n')
    rc, out = run_check(root)
    check(rc == 1 and "decoder message no longer in the hook source" in out, out)


@case
def untranslated_english_section_fails(root):
    en = EN.replace("## Appendix", "## New part\n\nNew text.\n\n## Appendix")
    build(root, en=en)
    rc, out = run_check(root)
    check(rc == 1 and "English section 'new-part' has no Hebrew translation marker" in out, out)


@case
def renamed_english_heading_fails(root):
    build(root)
    en = (root / "ONBOARDING.md").read_text(encoding="utf-8").replace("Part 1 — Basics", "Part 1 — Basic")
    (root / "ONBOARDING.md").write_bytes(en.encode("utf-8"))
    rc, out = run_check(root)
    check(rc == 1 and "marker 'part-1--basics': no such English section" in out, out)


@case
def crlf_and_bom_hash_the_same_as_lf(root):
    build(root)
    lf = (root / "ONBOARDING.md").read_bytes()
    (root / "ONBOARDING.md").write_bytes(b"\xef\xbb\xbf" + lf.replace(b"\n", b"\r\n"))
    rc, out = run_check(root)
    check(rc == 0, "a Windows checkout (CRLF/BOM) must not read as drift:\n" + out)


@case
def readme_partial_translation_is_allowed(root):
    build(root)  # README.he.md translates only the "Limits" section, and that is fine
    rc, out = run_check(root)
    check(rc == 0, out)


@case
def link_outside_the_repo_fails(root):
    # The file exists, beside the repository: still refused, and never read.
    repo = root / "repo"
    repo.mkdir()
    (root / "outside.md").write_text("# Out\n", encoding="utf-8")
    build(repo, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nראו [x](../outside.md).\n"))
    rc, out = run_check(repo)
    check(rc == 1 and "link target outside the repository: ../outside.md" in out, out)


@case
def absolute_and_drive_links_fail(root):
    build(root, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nראו [a](/abs.md) ו-[b](C:/x.md).\n"))
    rc, out = run_check(root)
    check(rc == 1 and "link target outside the repository: /abs.md" in out
          and "link target outside the repository: C:/x.md" in out, out)


@case
def link_that_leaves_and_comes_back_fails(root):
    # ../repo/ONBOARDING.md resolves back inside a checkout named repo; GitHub renders
    # it broken, so it is judged on its text first.
    repo = root / "repo"
    repo.mkdir()
    build(repo, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nראו [x](../repo/ONBOARDING.md).\n"))
    rc, out = run_check(repo)
    check(rc == 1 and "link target outside the repository: ../repo/ONBOARDING.md" in out, out)


@case
def link_through_a_subdirectory_passes(root):
    build(root, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nראו [x](hooks/../ONBOARDING.md#appendix).\n"))
    rc, out = run_check(root)
    check(rc == 0, out)


@case
def link_through_a_symlink_out_of_the_repo_fails(root):
    # Its text stays inside; where it resolves does not.
    repo = root / "repo"
    repo.mkdir()
    (root / "outdir").mkdir()
    (root / "outdir" / "x.md").write_text("# X\n", encoding="utf-8")
    try:
        os.symlink(root / "outdir", repo / "out", target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        if os.name != "nt":
            raise   # Linux and macOS can always make one: a failure there is a failure
        raise Skip(f"no symbolic link could be made here ({exc.__class__.__name__})")
    build(repo, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nראו [x](out/x.md).\n"))
    rc, out = run_check(repo)
    check(rc == 1 and "link target outside the repository: out/x.md" in out, out)


@case
def backslash_unc_and_lowercase_drive_links_fail(root):
    bs = chr(92)
    links = "[a](.." + bs + "outside.md) [b](//host/share/x.md) [c](c:/x.md)"
    build(root, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\n" + links + "\n"))
    rc, out = run_check(root)
    check(rc == 1 and "link target outside the repository: .." + bs + "outside.md" in out
          and "link target outside the repository: //host/share/x.md" in out
          and "link target outside the repository: c:/x.md" in out, out)


@case
def span_across_two_english_spans_fails(root):
    # Each English code span stands alone: joined, `install.sh git` would match.
    build(root, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nראו `install.sh git`.\n"))
    rc, out = run_check(root)
    check(rc == 1 and f"{HE_ONLY_FAIL}: `install.sh git`" in out, out)


@case
def cut_off_token_fails(root):
    # Inside an English code span, but cutting a token: not a command the English gives.
    build(root, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nראו `git push --for`.\n"))
    rc, out = run_check(root)
    check(rc == 1 and f"{HE_ONLY_FAIL}: `git push --for`" in out, out)


@case
def shortened_option_in_a_section_fails(root):
    # English `git push --force-with-lease`, Hebrew `git push --force`: a different command.
    build(root, en=EN.replace("`git push --force`", "`git push --force-with-lease`"))
    rc, out = run_check(root)
    check(rc == 1 and "Hebrew inline code not found in the English code: `git push --force`" in out, out)


@case
def he_only_span_from_english_prose_fails(root):
    # "Intro with" is English prose, not code: quoting it is not quoting a command.
    build(root, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nראו `Intro with`.\n"))
    rc, out = run_check(root)
    check(rc == 1 and f"{HE_ONLY_FAIL}: `Intro with`" in out, out)


@case
def section_span_from_english_prose_fails(root):
    build(root, he=HE.replace("הריצו:", "הריצו `Run this`:"))
    rc, out = run_check(root)
    check(rc == 1 and "Hebrew inline code not found in the English code: `Run this`" in out, out)


@case
def span_inside_one_english_code_span_passes(root):
    # Part of one code span still counts, as before.
    build(root, he=HE.replace("### ה. הודעות\n", "### ה. הודעות\n\nראו `push --force`.\n"))
    rc, out = run_check(root)
    check(rc == 0, out)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    if sys.flags.optimize:
        print("  FAIL assertions are disabled (python -O / PYTHONOPTIMIZE): a case that"
              " used a bare assert would pass without checking anything")
        return 1
    failed = skipped = 0
    for fn in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                fn(Path(tmp))
                print(f"   ok {fn.__name__}")
            except Skip as why:
                skipped += 1
                print(f"   skip {fn.__name__}: {why}")
            except Exception as exc:  # any other exception is a failure, never a skip
                failed += 1
                print(f"  FAIL {fn.__name__}: {type(exc).__name__}: {exc}")
    print(f"   {len(CASES) - failed - skipped}/{len(CASES)} translation-sync fixtures passed"
          + (f", {skipped} skipped" if skipped else ""))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
