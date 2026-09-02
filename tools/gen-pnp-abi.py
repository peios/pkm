#!/usr/bin/env python3
"""Generate the PNP ABI appendix of the Peios Kernel TRM from pkm/uapi/pkm/pnp.h.

Constant values and struct layouts are obtained by compiling a probe against
the real header, so the output cannot drift from the ABI.

This file owns the appendix outright and overwrites it wholesale. Nothing
hand-written may live there: prose about the ABI belongs in the notes
appendix beside it (§6.B), which no generator writes.

Usage:  python3 pkm/tools/gen-pnp-abi.py [--check]

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
HDR = UAPI / "pkm" / "pnp.h"
OUT = (ROOT / "learn/peios.product/3--advanced-peios.antho/300--trms.shelf"
       / "100--peios-kernel.book/6--network-policy/a1--pnp-abi.md")

DESCRIPTION = ("Every PNP ioctl number, event and status structure layout, "
               "counter record layout and constant, generated from the uapi "
               "header and measured by compilation.")

# Named-citation anchors for the stable constant groups, keyed by the
# leading words of each group's heading comment in the header.
GROUP_ANCHORS = [
    ("Which standing seat", "abi.seat-values"),
    ("Which rules layer", "abi.layer-values"),
    ("The verdict", "abi.verdict-values"),
    ("The story a REJECT", "abi.reject-kinds"),
    ("Traversal direction", "abi.direction-values"),
    ("Flow state", "abi.flow-state-values"),
    ("Event flags", "abi.event-flags"),
    ("Key-spec bits", "abi.keyspec-bits"),
]


def group_anchor(head):
    return next((n for k, n in GROUP_ANCHORS if head.startswith(k)), None)


DEFINE = re.compile(r"^#define\s+([A-Z_][A-Z0-9_]*)(\([^)]*\))?\s+(.+?)\s*$")
TRAILING = re.compile(r"/\*\s*(.*?)\s*\*/")


def esc(cell):
    return cell.replace("|", "\\|")


def join_continuations(raw_lines):
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
    line = re.sub(r"\*/\s*$", "", line.rstrip())
    line = re.sub(r"^\s*/?\*[ ]?", "", line)
    return line.rstrip()


def parse_header(path):
    """Return (constants, structs). constants: [(name, args, raw, comment, group)]."""
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


def probe(consts, structs):
    src = ['#include <stdio.h>', '#include <stddef.h>', '#include <stdint.h>',
           '#include <pkm/pnp.h>', "int main(void){"]
    for name, args, raw, _, _ in consts:
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


def fmt_value(name, raw, val):
    stripped = raw.lstrip("(").lower()
    if stripped.startswith("0x"):
        digits = re.match(r"0x([0-9a-f]+)", stripped).group(1)
        return f"`0x{val:0{max(len(digits), 2)}X}`"
    # An ioctl request number is a packed word; decimal hides its parts.
    if "_IOC_" in name or raw.startswith("_IO"):
        return f"`0x{val:08X}`"
    return f"`{val}`"


def table(head, rows):
    o = ["| " + " | ".join(esc(h) for h in head) + " |",
         "|" + "|".join("---" for _ in head) + "|"]
    for r in rows:
        o.append("| " + " | ".join(esc(str(c)) for c in r) + " |")
    return o


CODE_SPAN = re.compile(r"`[^`]*`")


def md_escape(text):
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
    blocks = comment_blocks(list(group or ()))
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


VALUES = {}


def emit_group(w, o, group, rows):
    head, blocks = shape_group(group)
    if head:
        anchor = group_anchor(head)
        w(f"*{md_escape(head)}.*" + (f" [*{anchor}]" if anchor else ""))
        w("")
    render_blocks(w, blocks)
    has_note = any(r[3] for r in rows)
    trows = []
    for name, args, raw, comment in rows:
        if raw.startswith('"'):
            val = f"`{raw}`"
        elif name in VALUES:
            val = fmt_value(name, raw, VALUES[name])
        else:
            val = f"`{raw}`"
        note = md_escape(comment.strip())
        trows.append([f"`{name}`", val] + ([note] if has_note else []))
    o += table(["Constant", "Value"] + (["Notes"] if has_note else []), trows)
    w("")


def group_runs(entries):
    runs = []
    for entry in entries:
        if not runs or runs[-1][0] != entry[4]:
            runs.append((entry[4], []))
        runs[-1][1].append(entry)
    return runs


def build():
    global VALUES
    consts, structs = parse_header(HDR)
    VALUES, sizes, offsets = probe(consts, structs)
    o = []
    w = o.append

    w("---")
    w("title: PNP ABI Reference")
    w(f"description: {DESCRIPTION}")
    w("---")
    w("")
    w("Every name, value, offset and size in this appendix is generated from")
    w("`pkm/uapi/pkm/pnp.h` by `pkm/tools/gen-pnp-abi.py`, with struct")
    w("layouts measured by compiling a probe against the real header.")
    w("Regenerate it whenever the ABI changes; do not edit it by hand. The")
    w("names here are the ones a program actually compiles")
    w("against. [*abi.pnp-generated-from-source]")
    w("")
    w("What a compiler cannot measure -- the device's read and poll")
    w("semantics, what each ioctl expects, the error vocabulary, and the")
    w("bounds that are not in the header -- is in the notes appendix, §6.B,")
    w("which this generator does not touch.")
    w("")

    ioctls = [c for c in consts if c[2].startswith("_IO")]
    if ioctls:
        w("## Ioctl requests [*abi.ioctl-numbers]")
        w("")
        w("Request numbers on `/dev/peios-pnp`, packed as `<linux/ioctl.h>`")
        w("packs them (direction, argument size, type `'N'`, number).")
        w("")
        rows = [[f"`{n}`", fmt_value(n, r, VALUES[n]), f"`{r}`"]
                for n, _, r, _, _ in ioctls if n in VALUES]
        o += table(["Constant", "Value", "Definition"], rows)
        w("")

    if any(s in sizes for s, _ in structs):
        w("## Structure layouts")
        w("")
        w("Offsets and sizes are measured, not declared.")
        w("")
        for sname, fields in structs:
            if sname not in sizes:
                continue
            w(f"### `struct {sname}` [*abi.struct-{sname.replace('_', '-')}]")
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

    w("## Constants")
    w("")
    w("Grouped as the header groups them.")
    w("")
    for group, rows in group_runs(c for c in consts if not c[2].startswith("_IO")):
        if not rows:
            continue
        emit_group(w, o, group, [(n, a, r, c) for n, a, r, c, _ in rows])

    text = "\n".join(o).rstrip() + "\n"
    return re.sub(r"\n{3,}", "\n\n", text)


def learn_is_absent():
    return not OUT.parent.parent.exists()


def main():
    if learn_is_absent():
        print(f"skipped: no learn/ checkout at {OUT.parent}", file=sys.stderr)
        return 0
    text = build()
    if "--check" in sys.argv:
        cur = OUT.read_text() if OUT.exists() else ""
        if cur != text:
            print(f"{OUT} is out of date; regenerate with gen-pnp-abi.py",
                  file=sys.stderr)
            return 1
        print("up to date")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(f"wrote {OUT} ({len(text.splitlines())} lines)")
    return 0


sys.exit(main())
