#!/usr/bin/env python3
"""Unit tests for _BCL_DEFPATH_SRC (hooks/lib/common.sh), scope-guard's definition-path check.

The source is read out of common.sh and exec'd, as the hooks run it. These cases need
no hook process: Windows path classification (forced, so it runs on every OS), the raw
patterns, the 8.3 heuristic, the verdict rules, hard-link lookups through a stub, and
the POSIX inode walk. test_hooks.sh runs the hook itself against real links on each OS.
Run:  python tests/test_definition_path.py   (exits non-zero on any failure)
"""
import os
import sys
import tempfile
from pathlib import Path

COMMON = Path(__file__).resolve().parent.parent / "hooks" / "lib" / "common.sh"
START = "IFS='' read -r -d '' _BCL_DEFPATH_SRC <<'DEFPATHPY' || true\n"


def load() -> dict:
    text = COMMON.read_text(encoding="utf-8")
    body = text[text.index(START) + len(START):]
    body = body[:body.index("\nDEFPATHPY\n") + 1]
    ns: dict = {}
    exec(compile(body, "_BCL_DEFPATH_SRC", "exec"), ns)
    return ns


D = load()
failures: list[str] = []
count = 0


def check(label: str, got, want) -> None:
    global count
    count += 1
    if got != want:
        failures.append(f"{label}: want {want!r}, got {got!r}")


def payload(path) -> dict:
    return {"tool_name": "Write", "tool_input": {"file_path": path, "content": "x"}}


# --- Windows namespaces (pure string logic; forced nt) ---
classify = D["_d_classify"]
for path, want in [
        (r"C:\repo\x.md", "local"),
        (r"\\host\share\x.md", "remote"),
        ("\\/host\\share\\x.md", "remote"),
        ("/\\host\\share\\x.md", "remote"),
        ("//host/share/x.md", "remote"),
        (r"\\?\C:\repo\x.md", "local"),
        (r"\\.\C:\repo\x.md", "local"),
        (r"\\?\UNC\host\share\x.md", "remote"),
        (r"\\?\UNC\localhost\c$\x.md", "cannot"),
        (r"\\?\Volume{0a1b}\repo\x.md", "local"),
        (r"\\?\GLOBALROOT\Device\HarddiskVolume3\x.md", "local"),
        (r"\\.\Volume{0a1b}\x.md", "cannot"),
        (r"\\.\pipe\x", "cannot"),
        (r"\\?\pipe\x", "cannot"),
        (r"\\wsl$\Ubuntu\home\x.md", "local"),
        (r"\\wsl.localhost\Ubuntu\home\x.md", "local"),
        (r"\\localhost\c$\x.md", "cannot"),
        (r"\\LOCALHOST\c$\x.md", "cannot"),
        (r"\\127.0.0.1\c$\x.md", "cannot"),
        (r"\\[::1]\c$\x.md", "cannot"),
        (r"\\0--1.ipv6-literal.net\c$\x.md", "cannot"),
        ("\\\\", "cannot")]:
    check(f"classify nt {path!r}", classify(path, True)[0], want)
check("classify nt drive form strips the prefix", classify(r"\\?\C:\repo\x.md", True)[1], r"C:\repo\x.md")
check("classify nt own host name", classify("\\\\" + __import__("socket").gethostname() + r"\c$\x", True)[0], "cannot")
check("classify posix: \\\\host is a relative name", classify(r"\\host\share\x.md", False)[0], "local")


# --- a remote UNC path never reaches the filesystem ---
class Touched(Exception):
    pass


def boom(*a, **k):
    raise Touched(a)


saved = {n: getattr(os.path, n) for n in ("realpath", "exists", "isdir")}
saved_os = {n: getattr(os, n) for n in ("stat", "lstat", "scandir")}
for n in saved:
    setattr(os.path, n, boom)
for n in saved_os:
    setattr(os, n, boom)
try:
    judge = D["_d_judge"]
    for path, want in [
            (r"\\files.example\share\x.md", "no"),
            ("\\/files.example\\share\\x.md", "no"),
            (r"\\files.example\share\.claude\agents\x.md", "yes"),
            (r"\\files.example\share\CLAUDE~1\agents\x.md", "yes"),
            (r"\\files.example\share\MCP~1.JSO", "yes"),
            (r"\\files.example\share\PROGRA~1\x.md", "no"),
            (r"\\localhost\c$\x.md", "cannot")]:
        try:
            got = judge(path, "C:/repo", {}, nt=True)[0]
        except Touched as e:
            got = f"touched the filesystem {e}"
        check(f"remote {path!r}", got, want)
finally:
    for n, f in saved.items():
        setattr(os.path, n, f)
    for n, f in saved_os.items():
        setattr(os, n, f)

# --- raw patterns (decided before any filesystem call) ---
raw = D["_d_raw_hit"]
for path, want in [
        ("/r/.claude/agents/a.md", True), ("/r/.claude/skills/s/SKILL.md", True),
        ("/r/.claude/commands/c.md", True), ("/r/.claude/plugins/p/hooks/hooks.json", True),
        (r"C:\r\.Claude\Skills\s\x.json", True), ("/r/sub/.claude/agents/a.md", True),
        (".claude/agents/a.md", True), (".claude//agents/a.md", True), (".claude/./agents/a.md", True),
        (".claude/x/../agents/a.md", True), ("/r/.mcp.json", True), ("/h/.claude.json", True),
        ("/r/.claude/agentsx/a.md", False), ("/r/docs/agents/a.md", False),
        ("/r/.claude/settings.json", False), ("/r/.claude/worktrees/w/src/agents/a.py", False),
        ("/r/docs/.claude-agents.md", False), ("/r/x.mcp.json", False), ("/r/.mcp.json.bak", False)]:
    check(f"raw {path!r}", raw(path), want)

# --- 8.3 heuristic (only used where realpath is unavailable) ---
short = D["_d_short_hit"]
for path, want in [("C:/r/CLAUDE~1/agents/a.md", True), ("C:/r/CL3F2A~1/x", True),
                   ("C:/h/CLAUDE~1.JSO", True), ("C:/r/MCP~1.JSO", True), ("C:/r/mcp~2.json", False),
                   ("C:/PROGRA~1/x", False), ("C:/Users/RUNNER~1/AppData", False), ("C:/r/DOCUME~1/x", False)]:
    check(f"8.3 {path!r}", short(path), want)

# --- verdict rules ---
verdict = D["bcl_definition_verdict"]
check("not an object -> unparsed", verdict(None, "/r", {})[0], "unparsed")
check("a list -> unparsed", verdict([1], "/r", {})[0], "unparsed")
check("no file_path -> nopath", verdict({"tool_input": {"content": "x"}}, "/r", {})[0], "nopath")
check("empty file_path -> nopath", verdict(payload(""), "/r", {})[0], "nopath")
check("file_path not a string -> cannot", verdict(payload(7), "/r", {})[0], "cannot")
check("NUL -> cannot", verdict(payload("src/a\x00b"), "/r", {})[0], "cannot")
check("any file_path anywhere counts", verdict({"x": {"y": [{"file_path": ".claude/agents/a.md"}]},
                                                "tool_input": {"file_path": "src/a.py"}}, "/r", {})[0], "yes")
deep: dict = {}
node = deep
for _ in range(80):
    node["k"] = {}
    node = node["k"]
check("payload deeper than the bound -> cannot", verdict(deep, "/r", {})[0], "cannot")

# --- real files: protected set, env relocation, hard links, the POSIX walk ---
# An upper-case prefix: the comparison keys are casefolded, and a walk that used a key
# instead of the real path would find nothing on a case-sensitive file system.
with tempfile.TemporaryDirectory(prefix="DefPathUC") as tmp:
    t = Path(tmp)
    proj, home = t / "proj", t / "home"
    for d in (proj / ".claude" / "agents", proj / "src", home / ".claude"):
        d.mkdir(parents=True)
    agent = proj / ".claude" / "agents" / "a.md"
    agent.write_text("x", encoding="utf-8")
    plain = proj / "src" / "plain.md"
    plain.write_text("x", encoding="utf-8")
    env_keep = {k: os.environ.get(k) for k in ("HOME", "USERPROFILE")}
    os.environ["HOME"] = os.environ["USERPROFILE"] = str(home)
    try:
        P = str(proj)
        check("ordinary file -> no", verdict(payload(str(plain)), P, {})[0], "no")
        check("user settings -> yes", verdict(payload(str(home / ".claude" / "settings.json")), P, {})[0], "yes")
        check("user .claude.json -> yes", verdict(payload(str(home / ".claude.json")), P, {})[0], "yes")
        check("user CLAUDE.md -> no", verdict(payload(str(home / ".claude" / "CLAUDE.md")), P, {})[0], "no")
        cfg = t / "cfg"
        envc = {"CLAUDE_CONFIG_DIR": str(cfg)}
        check("CLAUDE_CONFIG_DIR skills -> yes", verdict(payload(str(cfg / "skills" / "s" / "x.md")), P, envc)[0], "yes")
        check("CLAUDE_CONFIG_DIR .claude.json -> yes", verdict(payload(str(cfg / ".claude.json")), P, envc)[0], "yes")
        check("CLAUDE_CONFIG_DIR other -> no", verdict(payload(str(cfg / "notes.md")), P, envc)[0], "no")
        envp = {"CLAUDE_CODE_PLUGIN_CACHE_DIR": str(t / "pc")}
        check("plugin cache env -> yes", verdict(payload(str(t / "pc" / "m" / "h.json")), P, envp)[0], "yes")
        check("containment casefolds", D["_d_contained"](str(proj).upper() + "/.CLAUDE/AGENTS/x",
                                                         [D["_d_key"](str(proj / ".claude" / "agents"))], []), True)

        # Windows link-name enumeration, stubbed (nt forced): names are full paths.
        def names_with_agent(real):
            return [real, str(agent)]

        def names_alone(real):
            return [real]

        def names_fail(real):
            raise OSError("enumeration failed")

        check("hard link names include an agent -> yes",
              verdict(payload(str(plain)), P, {}, nt=True, link_names=names_with_agent)[0], "yes")
        check("hard link names, none protected -> no",
              verdict(payload(str(plain)), P, {}, nt=True, link_names=names_alone)[0], "no")
        check("hard link enumeration fails -> cannot",
              verdict(payload(str(plain)), P, {}, nt=True, link_names=names_fail)[0], "cannot")
        check("missing target needs no enumeration",
              verdict(payload(str(proj / "src" / "new.md")), P, {}, nt=True, link_names=names_fail)[0], "no")

        # realpath failing -> cannot
        rp = os.path.realpath
        os.path.realpath = boom
        try:
            check("realpath raises -> cannot", verdict(payload(str(plain)), P, {})[0], "cannot")
        finally:
            os.path.realpath = rp

        if os.name != "nt":
            hl = proj / "src" / "hl.md"
            os.link(agent, hl)
            check("posix hard link of an agent -> yes", verdict(payload(str(hl)), P, {})[0], "yes")
            other = proj / "src" / "o.md"
            os.link(plain, other)
            check("posix hard link of a plain file -> no", verdict(payload(str(other)), P, {})[0], "no")
            for i in range(3):
                (proj / ".claude" / "agents" / f"f{i}.md").write_text("x", encoding="utf-8")
            bound = D["_D_WALK_BOUND"]
            D["_D_WALK_BOUND"] = 2
            try:
                check("walk over its bound -> cannot", verdict(payload(str(other)), P, {})[0], "cannot")
            finally:
                D["_D_WALK_BOUND"] = bound
    finally:
        for k, v in env_keep.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

for f in failures:
    print("  FAIL " + f)
print(f"test_definition_path: {count - len(failures)} passed, {len(failures)} failed")
sys.exit(1 if failures else 0)
