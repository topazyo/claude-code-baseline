#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""claude-code-baseline :: tests/translation_sync.py

Keeps the Hebrew translations (ONBOARDING.he.md, README.he.md) honest against
the English sources they translate. The English files are authoritative; a
translation of a security document that silently goes stale misleads exactly
the readers least able to cross-check the English, so drift fails the build.

Each translated section in a Hebrew file starts with a marker naming the English
section it translates and the hash of that section's text when it was last
translated:

    <!-- he-sync: part-2--why-secure-by-default-for-an-ai-coding-agent sha256=0123abcd... -->

The section id is the GitHub anchor of the English `## ` heading ("preamble" is
the text before the first `## ` heading). A Hebrew section runs from its marker
to the next marker, to a `<!-- he-only ... -->` marker (content that exists only
in Hebrew), or to the end of the file.

Commands
  check                      verify every pair (used by tests/run.sh); exit 1 on any failure
  stamp FILE [ID ...]        after RETRANSLATING a section: record the current English
                             hash and remove its stale banner (all sections if no ID)
  mark-stale FILE ID [ID ...]  when an English section changed and the translation
                             cannot be updated in the same change: record the new hash
                             AND add a visible Hebrew banner saying the section may be
                             outdated and the English wins. Never `stamp` a section you
                             did not retranslate; that hides the drift this tool exists
                             to show.

What `check` verifies, per Hebrew file
  1. every marker names an English section that exists exactly once;
  2. its recorded hash equals the current English section's hash;
  3. for a complete translation (ONBOARDING), every English section has a marker;
  4. fenced code blocks with a language tag (runnable commands, JSON) are identical,
     as a multiset, in both directions; an untagged block (a diagram) kept in Hebrew
     must exist verbatim in the English section;
  5. every inline code span of the English section appears in the Hebrew section,
     and every Hebrew inline code span sits inside one of the English section's code
     spans or blocks, on token boundaries (not in its prose, not a cut-off token), so a
     translation can neither drop a command nor invent one;
  5a. content that exists only in Hebrew (before the first marker, he-only regions,
     he-note boxes) is not compared with a section, but it cannot invent a command
     either: each inline code span is in one of the English file's code spans or blocks
     (not its prose) or names an existing file in
     the repository (judged on the text first: no absolute, drive, backslash or `..`
     path), and inside the he-decoder table it may also quote one line of the hook
     source (an elided message's parts in order on that line); each fenced block is a
     block of the English file;
  6. no bidirectional-control characters anywhere (U+200E/F, U+202A-E, U+2066-9,
     U+061C): inside a command they are a copy-paste hazard ("Trojan Source");
  7. the file is wrapped in <div dir="rtl"> and every fenced block in
     <div dir="ltr">, so direction does not depend on renderer heuristics;
  8. every relative inline link (`[text](target)`) stays inside the repository (judged on its text first: no
     absolute, drive, backslash or escaping `..` target; then where it resolves), and
     every `#anchor` link resolves to a heading in the file it points at;
  9. every message fragment in the he-decoder table still occurs in the hook
     source (hooks/, install.sh), so the message decoder cannot drift silently.

Usage: python3 tests/translation_sync.py [--root DIR] COMMAND ...
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sys
import unicodedata
from collections import Counter
import posixpath
from pathlib import Path, PurePosixPath, PureWindowsPath

# (Hebrew file, English source, every English section must be translated?)
PAIRS: list[tuple[str, str, bool]] = [
    ("ONBOARDING.he.md", "ONBOARDING.md", True),
    ("README.he.md", "README.md", False),
]
DECODER_SOURCES = ("hooks", "install.sh")

MARKER_RE = re.compile(r"^<!-- he-sync: (\S+) sha256=([0-9a-f]+|PENDING) -->$")
HE_ONLY_RE = re.compile(r"^<!-- he-only\b.*-->$")
STALE_MARK = "<!-- he-stale -->"
HE_NOTE_RE = re.compile(r"<!-- he-note:start -->.*?<!-- he-note:end -->", re.DOTALL)
DECODER_RE = re.compile(r"<!-- he-decoder:start -->(.*?)<!-- he-decoder:end -->", re.DOTALL)
ELLIPSIS = "…"  # U+2026: the decoder table elides the variable part of a message with it
REPO_PATH_RE = re.compile(r"[A-Za-z0-9._/-]*[A-Za-z0-9][A-Za-z0-9._/-]*")
FENCE_RE = re.compile(r"^(?:>\s?)*\s*(```+)(.*)$")
BIDI_RE = re.compile("[\u200e\u200f\u202a-\u202e\u2066-\u2069\u061c]")
QUOTE_PREFIX_RE = re.compile(r"^(?:\s*>\s?)+", re.MULTILINE)
SPAN_RE = re.compile(r"(`+)(.+?)\1", re.DOTALL)
LINK_RE = re.compile(r"\]\(([^)\s]*)\)")
HASH_LEN = 16


def read_text(path: Path) -> str:
    """UTF-8 text with any BOM dropped and CRLF normalized, so Windows and Linux agree."""
    return path.read_bytes().decode("utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")


def section_hash(text: str) -> str:
    return hashlib.sha256(text.strip("\n").encode("utf-8")).hexdigest()[:HASH_LEN]


def strip_inline_markup(text: str) -> str:
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # [label](url) -> label
    return text.replace("`", "").replace("*", "")


def github_slug(heading: str) -> str:
    """GitHub's heading anchor: lowercase, keep letters/marks/digits/_/-/space, space -> '-'."""
    text = strip_inline_markup(heading).strip().lower()
    kept = "".join(
        ch for ch in text if ch in " -_" or unicodedata.category(ch)[0] in "LMN"
    )
    return kept.replace(" ", "-")


def outside_fences(lines: list[str]):
    """Yield (index, line) for lines that are not inside a fenced code block."""
    in_fence = False
    for i, line in enumerate(lines):
        if FENCE_RE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            yield i, line


def heading_slugs(text: str) -> set[str]:
    slugs: set[str] = set()
    seen: Counter[str] = Counter()
    for _, line in outside_fences(text.split("\n")):
        m = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if not m:
            continue
        base = github_slug(m.group(1))
        slugs.add(base if seen[base] == 0 else f"{base}-{seen[base]}")
        seen[base] += 1
    return slugs


def english_sections(text: str) -> tuple[dict[str, str], list[str]]:
    """Split an English doc at `## ` headings. Returns (id -> text, problems)."""
    lines = text.split("\n")
    starts = [(0, "preamble")]
    for i, line in outside_fences(lines):
        if line.startswith("## "):
            starts.append((i, github_slug(line[3:])))
    sections: dict[str, str] = {}
    problems: list[str] = []
    for n, (start, sid) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else len(lines)
        if sid in sections:
            problems.append(f"English heading id '{sid}' occurs more than once")
        sections[sid] = "\n".join(lines[start:end])
    return sections, problems


def hebrew_sections(text: str) -> list[tuple[str, str, int, str]]:
    """Return (id, recorded hash, marker line index, section text) per marker."""
    lines = text.split("\n")
    found = []
    for i, line in enumerate(lines):
        m = MARKER_RE.match(line)
        if m:
            found.append((i, m.group(1), m.group(2)))
    result = []
    for n, (i, sid, digest) in enumerate(found):
        end = found[n + 1][0] if n + 1 < len(found) else len(lines)
        for j in range(i + 1, end):
            if HE_ONLY_RE.match(lines[j]):
                end = j
                break
        result.append((sid, digest, i, "\n".join(lines[i + 1 : end])))
    return result


def fenced_blocks(text: str) -> list[tuple[str, str]]:
    """(language tag, normalized body) for every fenced block, blockquote prefixes removed."""
    blocks = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        m = FENCE_RE.match(lines[i])
        if not m:
            i += 1
            continue
        tag = m.group(2).strip()
        body = []
        i += 1
        while i < len(lines) and not FENCE_RE.match(lines[i]):
            body.append(QUOTE_PREFIX_RE.sub("", lines[i]))
            i += 1
        blocks.append((tag, "\n".join(body).strip("\n")))
        i += 1
    return blocks


def without_fences(text: str) -> str:
    lines = text.split("\n")
    return "\n".join(line for _, line in outside_fences(lines))


def inline_spans(text: str) -> list[str]:
    flat = QUOTE_PREFIX_RE.sub("", without_fences(text))
    spans = []
    for m in SPAN_RE.finditer(flat):
        span = m.group(2).replace("\\|", "|")
        spans.append(re.sub(r"\s+", " ", span).strip())
    return [s for s in spans if s]


def normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", QUOTE_PREFIX_RE.sub("", text))


def check_direction(he_text: str) -> list[str]:
    problems = []
    lines = he_text.split("\n")
    first = next((line for line in lines if line.strip()), "")
    if first.strip() != '<div dir="rtl">':
        problems.append('first line must be <div dir="rtl"> (explicit direction, not renderer heuristics)')
    in_fence = False
    for i, line in enumerate(lines):
        if not FENCE_RE.match(line):
            continue
        if not in_fence:
            prev = next(
                (lines[j] for j in range(i - 1, -1, -1) if lines[j].strip() not in ("", ">")),
                "",
            )
            if QUOTE_PREFIX_RE.sub("", prev).strip() != '<div dir="ltr">':
                problems.append(f'line {i + 1}: fenced block is not wrapped in <div dir="ltr">')
        in_fence = not in_fence
    return problems


def link_in_repo(he_path: Path, file_part: str, root: Path) -> bool:
    """A relative link target that stays inside the repository. Judged on the text
    first, as is_repo_path judges a path, so no absolute, drive or backslash target, and
    none whose `..` parts leave the repository even to come back in; then by where it
    resolves, which catches a link (symlink) inside the repository pointing out. The
    root is resolved too: resolve() expands 8.3 short names (a Windows runner's temp)."""
    if "\\" in file_part or PurePosixPath(file_part).is_absolute() or PureWindowsPath(file_part).drive:
        return False
    try:
        base = he_path.parent.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return False
    rel = posixpath.normpath(posixpath.join(base, file_part))
    if rel == ".." or rel.startswith("../"):
        return False
    try:
        (he_path.parent / file_part).resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def code_texts(text: str) -> list[str]:
    """Every inline code span and fenced block body of an English text, each on its own
    and whitespace-normalised. A Hebrew span must sit inside ONE of them: matched against
    a join, it could straddle two neighbouring spans and invent a command."""
    return [re.sub(r"\s+", " ", c) for c in list(inline_spans(text)) + [b[1] for b in fenced_blocks(text)]]


def in_code(span: str, codes: list[str]) -> bool:
    """The span sits inside one English code text, starting and ending on a token
    boundary: a Hebrew `git push --force` must not pass as part of an English
    `git push --force-with-lease`, nor a cut-off `--for` as part of `--force`."""
    pat = re.compile(r"(?<![\w-])" + re.escape(span) + r"(?![\w-])")
    return any(pat.search(c) for c in codes)


def check_links(he_path: Path, he_text: str, root: Path) -> list[str]:
    problems = []
    own = heading_slugs(he_text)
    for m in LINK_RE.finditer(without_fences(he_text)):
        target = m.group(1)
        if re.match(r"^[a-z][a-z0-9+.-]+:", target):
            continue  # external URL
        file_part, _, frag = target.partition("#")
        if file_part:
            if not link_in_repo(he_path, file_part, root):
                problems.append(f"link target outside the repository: {target}")
                continue
            dest = (he_path.parent / file_part).resolve()
            if not dest.exists():
                problems.append(f"link target does not exist: {target}")
                continue
            if frag and dest.suffix == ".md" and frag not in heading_slugs(read_text(dest)):
                problems.append(f"anchor not found in {file_part}: #{frag}")
        elif frag and frag not in own:
            problems.append(f"anchor not found in this file: #{frag}")
    return problems


def hook_corpus(root: Path) -> str:
    """The hook source the decoder table quotes (hooks/ *.sh and *.py, install.sh)."""
    corpus_parts = []
    for name in DECODER_SOURCES:
        path = root / name
        files = [path] if path.is_file() else sorted(
            p for p in path.rglob("*") if p.is_file() and p.suffix in (".sh", ".py")
        )
        corpus_parts += [read_text(p) for p in files]
    return "\n".join(corpus_parts)


def check_decoder(he_text: str, root: Path) -> list[str]:
    m = DECODER_RE.search(he_text)
    if not m:
        return []
    corpus = hook_corpus(root)
    problems, checked = [], 0
    for line in m.group(1).split("\n"):
        if not line.startswith("|") or re.match(r"^\|[\s:|-]+\|?$", line):
            continue
        first_cell = line.split(" | ")[0]
        spans = inline_spans(first_cell)
        if not spans:
            continue
        checked += 1
        if spans[0] not in corpus:
            problems.append(f"decoder message no longer in the hook source: {spans[0]!r}")
    if checked == 0:
        problems.append("he-decoder region found but no message rows were checked")
    return problems


def hebrew_only_regions(he_text: str) -> list[str]:
    """Text that exists only in Hebrew, so no English section is compared against it:
    what precedes the first he-sync marker, each he-only region (to the next marker or
    the end of the file), and each he-note box."""
    lines = he_text.split("\n")
    markers = [i for i, line in enumerate(lines) if MARKER_RE.match(line)]
    regions = ["\n".join(lines[: markers[0] if markers else len(lines)])]
    for i, line in enumerate(lines):
        if HE_ONLY_RE.match(line):
            end = next((j for j in markers if j > i), len(lines))
            regions.append("\n".join(lines[i + 1 : end]))
    regions += HE_NOTE_RE.findall(he_text)
    return regions


def is_repo_path(root: Path, span: str) -> bool:
    """A relative path inside the repository that exists. Judged on the text first, so a
    span that is absolute, anchored, has a drive, a backslash (a UNC or Windows path) or
    a `..` part never reaches the filesystem; the character set rules out the rest."""
    if not REPO_PATH_RE.fullmatch(span):
        return False
    if PurePosixPath(span).is_absolute() or PureWindowsPath(span).anchor:
        return False
    parts = PurePosixPath(span).parts
    if ".." in parts:
        return False
    # Walk it with exact case, so a case-insensitive filesystem (Windows, macOS) does
    # not accept a path that CI's Linux checkout would refuse.
    here = root
    for part in parts:
        if part == ".":
            continue
        try:
            if part not in os.listdir(here):
                return False
        except OSError:
            return False
        here = here / part
    return True


def in_hook_line(span: str, corpus_lines: list[str]) -> bool:
    """The span occurs in one line of the hook source. An elided message (`Blocked by …:`)
    matches when its parts occur in that order within a single line."""
    parts = [p for p in span.split(ELLIPSIS) if p]
    # At least one part with substance: `…:` or `a…b` would match almost any line.
    if not any(len("".join(p.split())) >= 3 for p in parts):
        return False
    for line in corpus_lines:
        pos = 0
        for part in parts:
            k = line.find(part, pos)
            if k < 0:
                break
            pos = k + len(part)
        else:
            return True
    return False


def check_hebrew_only(he_text: str, en_text: str, root: Path) -> list[str]:
    """Hebrew-only content is not a translation, but it may not invent a command either:
    every code span in it comes from one of the English file's code spans or blocks (not
    its prose) or names a file in the repository,
    and inside the he-decoder table it may also quote the hook source the table decodes.
    Every fenced block in it is a block of the English file."""
    en_codes = code_texts(en_text)
    en_blocks = fenced_blocks(en_text)
    en_tagged = {b for b in en_blocks if b[0]}
    en_untagged = {b[1] for b in en_blocks if not b[0]}
    corpus_lines: list[str] | None = None
    problems: list[str] = []
    for region in hebrew_only_regions(he_text):
        pieces = [(DECODER_RE.sub("", region), False)]
        pieces += [(table, True) for table in DECODER_RE.findall(region)]
        for text, in_decoder in pieces:
            for span in inline_spans(text):
                if in_code(span, en_codes) or is_repo_path(root, span):
                    continue
                if in_decoder:
                    if corpus_lines is None:
                        # whitespace collapsed as inline_spans collapses it in the span
                        corpus_lines = [re.sub(r"\s+", " ", x) for x in hook_corpus(root).split("\n")]
                    if in_hook_line(span, corpus_lines):
                        continue
                problems.append(
                    f"Hebrew-only content: inline code not found in the English code or the repository: `{span}`"
                )
            for tag, body in fenced_blocks(text):
                if (tag and (tag, body) not in en_tagged) or (not tag and body not in en_untagged):
                    problems.append(
                        f"Hebrew-only content: {tag or 'untagged'} block not in the English: {body[:60]!r}"
                    )
    return list(dict.fromkeys(problems))


def check_pair(root: Path, he_name: str, en_name: str, complete: bool) -> tuple[list[str], list[str]]:
    he_path, en_path = root / he_name, root / en_name
    if not he_path.exists():
        return [f"missing translation file {he_name}"], []
    he_text, en_text = read_text(he_path), read_text(en_path)
    en, problems = english_sections(en_text)
    stale: list[str] = []

    if BIDI_RE.search(he_text):
        lines = sorted({he_text.count("\n", 0, mm.start()) + 1 for mm in BIDI_RE.finditer(he_text)})
        problems.append(f"bidirectional-control characters on line(s) {lines[:10]}")
    problems += check_direction(he_text)
    problems += check_links(he_path, he_text, root)
    problems += check_decoder(he_text, root)
    problems += check_hebrew_only(he_text, en_text, root)

    sections = hebrew_sections(he_text)
    if not sections:
        problems.append("no he-sync markers found")
    ids = Counter(sid for sid, *_ in sections)
    problems += [f"section '{sid}' has {n} markers" for sid, n in ids.items() if n > 1]
    if complete:
        problems += [
            f"English section '{sid}' has no Hebrew translation marker"
            for sid in en
            if sid not in ids
        ]

    for sid, digest, _, he_sec in sections:
        if sid not in en:
            problems.append(f"marker '{sid}': no such English section (heading renamed or removed?)")
            continue
        en_sec = en[sid]
        if digest != section_hash(en_sec):
            problems.append(
                f"section '{sid}': the English text changed since it was translated. "
                f"Retranslate it, then run: tests/translation_sync.py stamp {he_name} {sid} "
                f"-- or, if it cannot be retranslated now: "
                f"tests/translation_sync.py mark-stale {he_name} {sid}"
            )
        if STALE_MARK in he_sec:
            stale.append(f"{he_name}: {sid}")

        # A he-note region is a translator's note that exists only in Hebrew (e.g. the
        # "about this translation" box); it is not a translation, so it is not compared.
        he_sec = HE_NOTE_RE.sub("", he_sec)
        en_blocks, he_blocks = fenced_blocks(en_sec), fenced_blocks(he_sec)
        en_tagged = Counter(b for b in en_blocks if b[0])
        he_tagged = Counter(b for b in he_blocks if b[0])
        for block in (en_tagged - he_tagged).elements():
            problems.append(f"section '{sid}': English {block[0]} block missing or altered in Hebrew: {block[1][:60]!r}")
        for block in (he_tagged - en_tagged).elements():
            problems.append(f"section '{sid}': Hebrew {block[0]} block not in the English: {block[1][:60]!r}")
        en_untagged = {b[1] for b in en_blocks if not b[0]}
        for _, body in (b for b in he_blocks if not b[0]):
            if body not in en_untagged:
                problems.append(f"section '{sid}': untagged Hebrew block not verbatim from the English: {body[:60]!r}")

        he_spans = set(inline_spans(he_sec))
        en_codes = code_texts(en_sec)
        for span in sorted(set(inline_spans(en_sec)) - he_spans):
            problems.append(f"section '{sid}': inline code missing in Hebrew: `{span}`")
        for span in sorted(he_spans):
            if not in_code(span, en_codes):
                problems.append(f"section '{sid}': Hebrew inline code not found in the English code: `{span}`")
    return [f"{he_name}: {p}" for p in problems], stale


def cmd_check(root: Path) -> int:
    failures, stale = [], []
    for he_name, en_name, complete in PAIRS:
        f, s = check_pair(root, he_name, en_name, complete)
        failures += f
        stale += s
    for line in stale:
        print(f"   note: marked possibly outdated (English changed, not yet retranslated): {line}")
    if failures:
        for line in failures:
            print(f"  FAIL: {line}")
        return 1
    print(f"   ok {len(PAIRS)} translation(s) in sync with their English sources")
    return 0


def stale_banner(en_name: str, sid: str) -> list[str]:
    return [
        STALE_MARK,
        "> ⚠️ **ייתכן שהסעיף הזה לא מעודכן.** הסעיף המקביל באנגלית השתנה אחרי שתורגם.",
        f"> במקרה של סתירה, הגרסה האנגלית קובעת: [המקור באנגלית]({en_name}#{sid}).",
        "",
    ]


def rewrite(root: Path, he_name: str, wanted: list[str], mark_stale: bool) -> int:
    en_name = next((e for h, e, _ in PAIRS if h == he_name), None)
    if en_name is None:
        print(f"unknown translation file: {he_name}", file=sys.stderr)
        return 2
    he_path = root / he_name
    lines = read_text(he_path).split("\n")
    en, problems = english_sections(read_text(root / en_name))
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 2
    present = [sid for sid, *_ in hebrew_sections("\n".join(lines))]
    targets = wanted or present
    unknown = [sid for sid in targets if sid not in present or sid not in en]
    if unknown:
        print(f"no such section (in {he_name} and {en_name}): {', '.join(unknown)}", file=sys.stderr)
        return 2
    out: list[str] = []
    i = 0
    while i < len(lines):
        m = MARKER_RE.match(lines[i])
        if not m or m.group(1) not in targets:
            out.append(lines[i])
            i += 1
            continue
        sid = m.group(1)
        out.append(f"<!-- he-sync: {sid} sha256={section_hash(en[sid])} -->")
        i += 1
        if i < len(lines) and lines[i] == STALE_MARK:  # drop an existing banner
            i += 1
            while i < len(lines) and lines[i].startswith(">"):
                i += 1
            if i < len(lines) and lines[i] == "":
                i += 1
        if mark_stale:
            out += stale_banner(en_name, sid)
    he_path.write_bytes("\n".join(out).encode("utf-8"))
    verb = "marked stale" if mark_stale else "stamped"
    print(f"{verb}: {', '.join(targets)}")
    return 0


def main(argv: list[str]) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):  # a Windows console is not UTF-8 by default
            stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check")
    p_stamp = sub.add_parser("stamp")
    p_stamp.add_argument("file")
    p_stamp.add_argument("ids", nargs="*")
    p_stale = sub.add_parser("mark-stale")
    p_stale.add_argument("file")
    p_stale.add_argument("ids", nargs="+")
    args = parser.parse_args(argv)
    if args.cmd == "check":
        return cmd_check(args.root)
    return rewrite(args.root, args.file, args.ids, mark_stale=args.cmd == "mark-stale")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
