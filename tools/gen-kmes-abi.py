#!/usr/bin/env python3
"""Generate the KMES ABI appendix of the Peios Kernel TRM from pkm/uapi/pkm/kmes.h.

Constant values and struct layouts are obtained by compiling a probe against
the real headers, so the output cannot drift from the ABI.

This file owns the appendix outright and overwrites it wholesale. Nothing
hand-written may live there: prose about the ABI belongs in the notes
appendix beside it, which no generator writes.

Usage:  python3 pkm/tools/gen-kmes-abi.py [--check]

Writes the appendix into learn/. With --check, exits non-zero if the file on
disk differs from what would be generated, without writing.
"""
import re
import subprocess
import sys
import tempfile
import pathlib
import textwrap

ROOT = pathlib.Path(__file__).resolve().parents[2]
UAPI = ROOT / "pkm" / "uapi"
HDR = UAPI / "pkm" / "kmes.h"
TRACE_H = UAPI / "pkm" / "trace.h"
SYSCALL_H = UAPI / "pkm" / "syscall.h"
KMES_SRC = ROOT / "pkm" / "kmes"
OUT = (ROOT / "learn/peios.product/3--advanced-peios.antho/300--trms.shelf"
       / "100--peios-kernel.book/2--kmes/a1--kmes-abi.md")

# The page's own identity, not prose about the ABI. learn CI fails a deploy
# on an article with no description (learn 3362f6d), so it is emitted here
# rather than left in a file the generator overwrites wholesale.
DESCRIPTION = ("Every KMES syscall number, structure layout, ring-buffer "
               "offset and constant, generated from the uapi headers and "
               "measured by compilation.")

DEFINE = re.compile(r"^#define\s+([A-Z_][A-Z0-9_]*)(\([^)]*\))?\s+(.+?)\s*$")
TRAILING = re.compile(r"/\*\s*(.*?)\s*\*/")
# The header cites the PSD series, which this manual replaces. Drop those
# citations rather than emit stale cross-references into the TRM.
PSD_REF = re.compile(r"(?:See\s+)?PSD-\d+(?:\s*§[\d.]+)?[,;:]?\s*", re.I)


def esc(cell):
    """A markdown table cell: a pipe inside one silently breaks the row."""
    return cell.replace("|", "\\|")


def join_continuations(raw_lines):
    """A #define spanning two lines yields garbage unless the lines are joined."""
    lines, buf = [], None
    for ln in raw_lines:
        if buf is not None:
            buf = buf[:-1].rstrip() + " " + ln.strip()
        elif ln.rstrip().endswith("\\"):
            buf = ln.rstrip()
            continue
        else:
            lines.append(ln)
            continue
        if buf.rstrip().endswith("\\"):
            continue
        lines.append(buf)
        buf = None
    if buf is not None:
        lines.append(buf.replace("\\", " "))
    return lines


def strip_comment_markers(line):
    """Remove a comment line's leading ` * ` and trailing `*/`, keeping indent.

    Indentation inside a block comment is load-bearing in this header: the
    event-header and ring-metadata groups lay their fields out as indented
    listings, and flattening those into a paragraph destroys them. Only the
    marker and one following space are consumed, so a field line keeps the
    indentation that distinguishes it from prose.
    """
    line = re.sub(r"\*/\s*$", "", line.rstrip())
    line = re.sub(r"^\s*/?\*[ ]?", "", line)
    return line.rstrip()


def parse_header(path):
    """Return (constants, structs). constants: [(name, args, raw, comment, group)].

    `group` is a tuple of comment lines rather than a joined string, so the
    renderer can tell an indented listing from a paragraph.
    """
    lines = join_continuations(path.read_text().splitlines())
    consts, group, pending = [], (), None
    for line in lines:
        s = line.strip()
        if s.startswith("/*"):
            pending = [strip_comment_markers(line)]
            if s.endswith("*/"):
                group = tuple(pending)
                pending = None
            continue
        if pending is not None:
            pending.append(strip_comment_markers(line))
            if s.endswith("*/"):
                group = tuple(pending)
                pending = None
            continue
        m = DEFINE.match(line)
        if not m:
            continue
        name, args, rest = m.group(1), m.group(2), m.group(3)
        if name.startswith("_UAPI"):
            continue
        tc = TRAILING.search(rest)
        comment = tc.group(1) if tc else ""
        raw = TRAILING.sub("", rest).strip()
        consts.append((name, args, raw, comment, group))
    text = path.read_text()
    structs = []
    for m in re.finditer(r"struct\s+(\w+)\s*\{(.*?)\}\s*;", text, re.S):
        name = m.group(1)
        body = re.sub(r"/\*.*?\*/", "", m.group(2), flags=re.S)
        fields = []
        for fm in re.finditer(r"(__\w+|\w[\w ]*?)\s+(\w+)\s*(\[(\w+)\])?\s*;", body):
            fields.append((fm.group(1).strip(), fm.group(2), fm.group(4)))
        if fields:
            structs.append((name, fields))
    return consts, structs


SYSDEF = re.compile(r"SYSCALL_DEFINE(\d)\(\s*(\w+)\s*(.*?)\)\s*\n", re.S)


def syscall_signatures():
    """Map syscall name -> C signature, read from the SYSCALL_DEFINE sites."""
    sigs = {}
    for c in sorted(KMES_SRC.glob("*.c")):
        for m in SYSDEF.finditer(c.read_text()):
            argc, name, rest = int(m.group(1)), m.group(2), m.group(3)
            rest = re.sub(r"\s+", " ", rest).strip().lstrip(",").strip()
            if argc == 0 or not rest:
                sigs[name] = "void"
                continue
            parts = [x.strip() for x in rest.split(",")]
            args = []
            for i in range(0, len(parts) - 1, 2):
                ctype, pname = parts[i], parts[i + 1]
                args.append(f"{ctype} {pname}" if "*" not in ctype
                            else f"{ctype}{pname}")
            sigs[name] = ", ".join(args)
    return sigs


def probe(consts, structs, syscall_consts):
    """Compile a probe to resolve constant values and struct layouts."""
    src = ['#include <stdio.h>', '#include <stddef.h>', '#include <stdint.h>',
           '#include <pkm/kmes.h>', '#include <pkm/syscall.h>',
           '#include <pkm/trace.h>', "int main(void){"]
    for name, args, raw, _, _ in consts + syscall_consts:
        if args or raw.startswith('"'):
            continue
        src.append(f'  printf("C\\t{name}\\t%llu\\n", (unsigned long long)({name}));')
    for sname, fields in structs:
        src.append(f'  printf("S\\t{sname}\\t%zu\\n", sizeof(struct {sname}));')
        for _, fname, _ in fields:
            src.append(f'  printf("F\\t{sname}\\t{fname}\\t%zu\\t%zu\\n",'
                       f' offsetof(struct {sname}, {fname}),'
                       f' sizeof(((struct {sname} *)0)->{fname}));')
    src.append("  return 0;}")
    with tempfile.TemporaryDirectory() as td:
        c = pathlib.Path(td) / "probe.c"
        c.write_text("\n".join(src))
        exe = pathlib.Path(td) / "probe"
        subprocess.run(["gcc", "-I", str(UAPI), "-o", str(exe), str(c)],
                       check=True, capture_output=True)
        out = subprocess.run([str(exe)], check=True, capture_output=True,
                             text=True).stdout
    values, sizes, offsets = {}, {}, {}
    for line in out.splitlines():
        p = line.split("\t")
        if p[0] == "C":
            values[p[1]] = int(p[2])
        elif p[0] == "S":
            sizes[p[1]] = int(p[2])
        elif p[0] == "F":
            offsets.setdefault(p[1], []).append((p[2], int(p[3]), int(p[4])))
    return values, sizes, offsets


def fmt_value(raw, val):
    """Render a constant's value the way the header writes it."""
    stripped = raw.lstrip("(").lower()
    if stripped.startswith("0x"):
        digits = re.match(r"0x([0-9a-f]+)", stripped).group(1)
        return f"`0x{val:0{max(len(digits), 2)}X}`"
    # A privilege bit is written as a shift because the bit index is the
    # meaningful part; decimal 2097152 hides which bit that is.
    if "<<" in raw:
        return f"`0x{val:016X}` ({raw.strip('()')})"
    return f"`{val}`"


def table(head, rows):
    """Render a markdown table, escaping pipes in every cell."""
    o = ["| " + " | ".join(esc(h) for h in head) + " |",
         "|" + "|".join("---" for _ in head) + "|"]
    for r in rows:
        o.append("| " + " | ".join(esc(str(c)) for c in r) + " |")
    return o


CODE_SPAN = re.compile(r"`[^`]*`")


def md_escape(text):
    """Escape markdown-active characters in prose taken from a C comment.

    A comment says `KMES_ORIGIN_*` and `KMES_EVENT_*_OFFSET` in one
    paragraph; markdown reads the two asterisks as an emphasis pair and
    italicises everything between them. Backtick spans are left alone --
    the header uses them deliberately, and escaping inside one would print
    the backslash.
    """
    def esc_run(run):
        return run.replace("*", r"\*").replace("<", "&lt;").replace(">", "&gt;")

    out, pos = [], 0
    for m in CODE_SPAN.finditer(text):
        out.append(esc_run(text[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(esc_run(text[pos:]))
    return "".join(out)


def comment_blocks(lines):
    """Split comment lines into flush prose runs and indented literal runs.

    A run of indented lines is a listing the author aligned by hand; it is
    reproduced verbatim. A run of flush lines is prose and is rewrapped.
    """
    blocks = []
    for line in lines:
        if not line.strip():
            blocks.append(None)
            continue
        kind = "pre" if line[:1].isspace() else "prose"
        if not blocks or blocks[-1] is None or blocks[-1][0] != kind:
            blocks.append((kind, []))
        blocks[-1][1].append(line)
    return [b for b in blocks if b]


def shape_group(group):
    """Split a group comment into a short heading and the blocks below it.

    kmes.h comments several groups at paragraph length. Emitting one of
    those as a single italic line -- which is all a short group needs --
    produces a fifteen-line italic run, so a long comment is split at its
    first sentence and the remainder set as prose. Headings are not
    title-cased: several open with an identifier.
    """
    blocks = comment_blocks([PSD_REF.sub("", ln) for ln in group or ()])
    if not blocks:
        return "", []
    if blocks[0][0] != "prose":
        return "", blocks
    first = re.sub(r"\s+", " ", " ".join(blocks[0][1])).strip()
    parts = re.split(r"(?<=\.)\s+", first, maxsplit=1)
    head = parts[0].rstrip(".")
    if len(head) > 90:
        return "", blocks
    rest = parts[1].strip() if len(parts) > 1 else ""
    tail = ([("prose", [rest])] if rest else []) + blocks[1:]
    return head, tail


def render_blocks(w, blocks):
    """Write comment blocks: prose rewrapped, indented listings verbatim."""
    for kind, lines in blocks:
        if kind == "pre":
            pad = min(len(ln) - len(ln.lstrip()) for ln in lines)
            w("```text")
            for ln in lines:
                w(ln[pad:])
            w("```")
        else:
            text = re.sub(r"\s+", " ", " ".join(lines)).strip()
            if not text:
                continue
            for chunk in textwrap.wrap(md_escape(text), 72):
                w(chunk)
        w("")


def emit_group(w, o, group, rows):
    """Write one group's heading, prose and constant table."""
    head, blocks = shape_group(group)
    if head:
        w(f"*{md_escape(head)}.*")
        w("")
    render_blocks(w, blocks)
    has_note = any(r[3] for r in rows)
    trows = []
    for name, args, raw, comment in rows:
        if raw.startswith('"'):
            val = f"`{raw}`"
        elif name in VALUES:
            val = fmt_value(raw, VALUES[name])
        else:
            val = f"`{raw}`"
        note = md_escape(PSD_REF.sub("", comment).strip())
        trows.append([f"`{name}`", val] + ([note] if has_note else []))
    o += table(["Constant", "Value"] + (["Notes"] if has_note else []), trows)
    w("")


VALUES = {}


def group_runs(entries):
    """Group consecutive constants by their preceding comment block."""
    runs = []
    for entry in entries:
        if not runs or runs[-1][0] != entry[4]:
            runs.append((entry[4], []))
        runs[-1][1].append(entry)
    return runs


def build():
    global VALUES
    consts, structs = parse_header(HDR)
    syscall_consts = [c for c in parse_header(SYSCALL_H)[0]
                      if c[0].startswith("SYS_KMES_")]
    # trace.h is the single source of truth for the kacs:, kmes: and lcs:
    # tracepoint codes alike. Only the KMES ones belong here; the others are
    # generated into the KACS and LCS ABI appendices by their own generators.
    trace_consts = [c for c in parse_header(TRACE_H)[0]
                    if c[0].startswith("KMES_")]
    VALUES, sizes, offsets = probe(consts + trace_consts, structs,
                                   syscall_consts)
    o = []
    w = o.append

    w("---")
    w("title: KMES ABI Reference")
    w(f"description: {DESCRIPTION}")
    w("---")
    w("")
    w("Every name, value, offset and size in this appendix is generated from")
    w("`pkm/uapi/pkm/kmes.h` by `pkm/tools/gen-kmes-abi.py`, with struct")
    w("layouts measured by compiling a probe against the real header.")
    w("Regenerate it whenever the ABI changes; do not edit it by hand. The")
    w("names here are the ones a program actually compiles against.")
    w("")
    w("What a compiler cannot measure -- the error vocabulary of each")
    w("syscall, the privilege each requires by name, what the configuration")
    w("keys do, and the implementation bounds that are not in the header --")
    w("is in the notes appendix, §2.B, which this generator does not touch.")
    w("")

    # --- syscalls -------------------------------------------------------
    w("## Syscall numbers")
    w("")
    w("Signatures are read from the `SYSCALL_DEFINE` sites in `pkm/kmes/`.")
    w("")
    sigs = syscall_signatures()
    rows = []
    for name, _, _, _, _ in syscall_consts:
        fn = name.replace("SYS_", "").lower()
        sig = sigs.get(fn)
        rows.append([VALUES[name], f"`{name}`",
                     f"`{fn}({sig})`" if sig else ""])
    o += table(["Number", "Constant", "Signature"], sorted(rows))
    w("")

    # --- structures -----------------------------------------------------
    if any(s in sizes for s, _ in structs):
        w("## Structure layouts")
        w("")
        w("Offsets and sizes are measured, not declared.")
        w("")
        for sname, fields in structs:
            if sname not in sizes:
                continue
            w(f"### `struct {sname}`")
            w("")
            w(f"Total size {sizes[sname]} bytes.")
            w("")
            fo = {f[0]: f for f in offsets.get(sname, [])}
            rows = []
            for ctype, fname, arr in fields:
                if fname not in fo:
                    continue
                _, off, sz = fo[fname]
                disp = f"`{ctype}{'[' + arr + ']' if arr else ''}`"
                rows.append([off, sz, disp, f"`{fname}`"])
            o += table(["Offset", "Size", "Type", "Field"], rows)
            w("")

    # --- grouped constants ----------------------------------------------
    w("## Constants")
    w("")
    w("Grouped as the header groups them.")
    w("")
    for group, rows in group_runs(consts):
        if not rows:
            continue
        emit_group(w, o, group, [(n, a, r, c) for n, a, r, c, _ in rows])

    if trace_consts:
        w("## Tracepoint diagnostic codes")
        w("")
        w("From `uapi/pkm/trace.h`. These are a diagnostic contract for")
        w("ftrace, perf and eBPF consumers, letting a tool decode a `kmes:`")
        w("event's `reason`, `op` or `state` field without recompiling")
        w("against a specific kernel. No KMES syscall accepts or returns")
        w("them, and values are append-only.")
        w("")
        for group, rows in group_runs(trace_consts):
            emit_group(w, o, group, [(n, a, r, c) for n, a, r, c, _ in rows])

    text = "\n".join(o).rstrip() + "\n"
    return re.sub(r"\n{3,}", "\n\n", text)


def learn_is_absent():
    """True when there is no learn/ checkout beside pkm/ to write into.

    The appendices live in a sibling repository. A pkm checkout on its own
    is a legitimate state, and so is a build container that mounts only
    pkm/ -- neither is drift, and reporting it as drift is a false alarm
    that trains people to ignore the gate.
    """
    return not OUT.parent.exists()


def main():
    if learn_is_absent():
        print(f"skipped: no learn/ checkout at {OUT.parent}", file=sys.stderr)
        return 0
    text = build()
    if "--check" in sys.argv:
        cur = OUT.read_text() if OUT.exists() else ""
        if cur != text:
            print(f"{OUT} is out of date; regenerate with gen-kmes-abi.py",
                  file=sys.stderr)
            return 1
        print("up to date")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(f"wrote {OUT} ({len(text.splitlines())} lines)")
    return 0


sys.exit(main())
