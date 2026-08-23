#!/usr/bin/env python3
"""Generate the KACS ABI appendix of the Peios Kernel TRM from pkm/uapi/pkm/.

Constant values and struct layouts are obtained by compiling a probe program
against the real headers, so the output cannot drift from the ABI.

This file owns the appendix outright and overwrites it wholesale. Nothing
hand-written may live there: prose about the ABI belongs in the notes
appendix beside it, which no generator writes.

Usage:  python3 pkm/tools/gen-kacs-abi.py [--check]

Writes the appendix into learn/. With --check, exits non-zero if the file on
disk differs from what would be generated, without writing.
"""
import re, subprocess, sys, tempfile, pathlib, os, textwrap

ROOT = pathlib.Path(__file__).resolve().parents[2]
UAPI = ROOT / "pkm" / "uapi"
HDRS = UAPI / "pkm"
OUT = (ROOT / "learn/peios.product/3--advanced-peios.antho/300--trms.shelf"
       / "100--peios-kernel.book/3--kacs/a1--kacs-abi.md")

# Headers making up the KACS ABI. kmes.h and lcs.h belong to their own
# chapters; trace.h is generated separately.
KACS_HEADERS = ["syscall.h", "token.h", "access.h", "file.h",
                "process.h", "psb.h", "sd.h", "sid.h"]

# The page's own identity, not prose about the ABI. learn CI fails a deploy
# on an article with no description (learn 3362f6d), so this cannot be left
# to whoever last edited the file: the generator overwrites it wholesale.
DESCRIPTION = ("Every KACS syscall number, structure layout, constant and "
               "enumeration, generated from the uapi headers and measured by "
               "compilation.")


DEFINE = re.compile(r"^#define\s+([A-Z_][A-Z0-9_]*)(\([^)]*\))?\s+(.+?)\s*$")
TRAILING = re.compile(r"/\*\s*(.*?)\s*\*/")


def strip_comments(text):
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def parse_header(path):
    """Return (constants, structs). constants: [(name, args, raw, comment, group)]."""
    raw_lines = path.read_text().splitlines()
    # Join backslash line-continuations so multi-line #defines parse as one.
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
    consts, group, pending = [], None, []
    for line in lines:
        s = line.strip()
        if s.startswith("/*") or (pending and not s.startswith("#define")):
            if s.startswith("/*"):
                pending = [s.lstrip("/* ").rstrip("*/ ").strip()]
            elif s.startswith("*") and pending is not None:
                pending.append(s.lstrip("* ").rstrip("*/ ").strip())
            if s.endswith("*/") and pending:
                group = " ".join(x for x in pending if x).strip()
                pending = []
            continue
        m = DEFINE.match(line)
        if not m:
            if s and not s.startswith("#"):
                group = group  # keep
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
        name, body = m.group(1), strip_comments(m.group(2))
        fields = []
        for fm in re.finditer(r"(__\w+|\w[\w ]*?)\s+(\w+)\s*(\[(\w+)\])?\s*;", body):
            fields.append((fm.group(1).strip(), fm.group(2), fm.group(4)))
        if fields:
            structs.append((name, fields))
    return consts, structs


SYSDEF = re.compile(
    r"SYSCALL_DEFINE(\d)\(\s*(\w+)\s*(.*?)\)\s*\n", re.S)


def syscall_signatures():
    """Map syscall name -> C signature, read from the SYSCALL_DEFINE sites."""
    sigs = {}
    for c in sorted((ROOT / "pkm" / "kacs").glob("*.c")):
        text = c.read_text()
        for m in SYSDEF.finditer(text):
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


def probe(all_consts, all_structs):
    """Compile a probe to resolve constant values and struct layouts."""
    src = ['#include <stdio.h>', '#include <stddef.h>', '#include <stdint.h>']
    for h in KACS_HEADERS:
        src.append(f'#include <pkm/{h}>')
    src.append("int main(void){")
    for name, args, _, _, _ in all_consts:
        if args:
            continue
        src.append(f'  printf("C\\t{name}\\t%llu\\n", (unsigned long long)({name}));')
    for sname, fields in all_structs:
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
        out = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout
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


# The uapi headers cite the PSD series, which this manual replaces. Drop
# those citations rather than emit stale cross-references into the TRM.
PSD_REF = re.compile(r"\s*(See\s+)?PSD-\d+[^.]*\.", re.I)


def shape_group(text):
    """Split a header block comment into a short heading and a body."""
    if not text:
        return "", ""
    text = PSD_REF.sub("", text).strip()
    text = re.sub(r"\s+", " ", text)
    parts = re.split(r"(?<=\.)\s+", text, maxsplit=1)
    head = parts[0].rstrip(".")
    body = parts[1].strip() if len(parts) > 1 else ""
    if len(head) > 90:
        return "", text
    return head, body


def fmt_value(name, raw, val):
    """Render a constant's value the way the header writes it, plus decimal."""
    if raw.lstrip("(").lower().startswith("0x"):
        width = len(raw.strip("()U ").replace("0x", "").replace("0X", ""))
        hexs = f"0x{val:0{max(width,2)}X}"
        return f"`{hexs}`" + (f" ({val})" if val < 100000 else "")
    if raw.lstrip("(").startswith("_IO"):
        return f"`0x{val:08X}`"
    if val >= 1 << 20 and (val & (val - 1)) == 0:
        return f"`0x{val:X}` ({val})"
    return f"`{val}`"


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
    check = "--check" in sys.argv
    consts, structs = [], []
    per_header = {}
    for h in KACS_HEADERS:
        c, s = parse_header(HDRS / h)
        per_header[h] = (c, s)
        consts += c
        structs += s
    values, sizes, offsets = probe(consts, structs)

    o = []
    w = o.append
    w("---")
    w("title: KACS ABI Reference")
    w(f"description: {DESCRIPTION}")
    w("---")
    w("")
    w("Every name, value, offset and size in this appendix is generated")
    w("from `pkm/uapi/pkm/` by `pkm/tools/gen-kacs-abi.py`, with struct")
    w("layouts measured by compiling a probe against the real headers.")
    w("Regenerate it whenever the ABI changes; do not edit it by hand.")
    w("")
    w("The names here are the ones a program actually compiles against.")
    w("Everything about the ABI a compiler cannot measure -- token query")
    w("payload shapes, the specification spellings that differ from these")
    w("names, what is documented elsewhere, and the kernel configuration")
    w("-- is in the notes appendix, §3.D, which this generator does not")
    w("touch.")
    w("")

    # --- syscalls
    w("## Syscall numbers")
    w("")
    w("Signatures are read from the `SYSCALL_DEFINE` sites in `pkm/kacs/`.")
    w("")
    w("| Number | Constant | Signature |")
    w("|---:|---|---|")
    sigs = syscall_signatures()
    sysc = [(values[n], n) for n, a, r, c, g in per_header["syscall.h"][0]
            if n in values and n.startswith("SYS_KACS_")]
    for v, n in sorted(sysc):
        fn = n.replace("SYS_", "").lower()
        sig = sigs.get(fn)
        w(f"| {v} | `{n}` | " + (f"`{fn}({sig})`" if sig else "") + " |")
    w("")
    others = sorted((values[n], n) for n, a, r, c, g in per_header["syscall.h"][0]
                    if n in values and not n.startswith("SYS_KACS_"))
    if others:
        lo, hi = others[0][0], others[-1][0]
        w(f"`uapi/pkm/syscall.h` also registers the KMES and LCS numbers,")
        w(f"{lo}\u2013{hi}, documented in their own chapters.")
        w("")

    # --- structs
    w("## Structure layouts")
    w("")
    for sname, fields in structs:
        if sname not in sizes:
            continue
        w(f"### `struct {sname}`")
        w("")
        w(f"Total size {sizes[sname]} bytes.")
        w("")
        w("| Offset | Size | Type | Field |")
        w("|---:|---:|---|---|")
        by_name = {f[0]: f for f in offsets.get(sname, [])}
        for ctype, fname, arr in fields:
            if fname not in by_name:
                continue
            _, off, sz = by_name[fname]
            disp = f"`{ctype}`" + (f"`[{arr}]`" if arr else "")
            w(f"| {off} | {sz} | {disp} | `{fname}` |")
        w("")

    # --- constants by header
    titles = {
        "token.h": "Token constants",
        "access.h": "AccessCheck constants",
        "file.h": "File and open constants",
        "process.h": "Process access rights",
        "psb.h": "Process mitigation bits",
        "sd.h": "Security descriptor constants",
        "sid.h": "SID constants",
    }
    for h in KACS_HEADERS:
        if h == "syscall.h":
            continue
        cs = [c for c in per_header[h][0]]
        if not cs:
            continue
        w(f"## {titles.get(h, h)}")
        w("")
        w(f"From `uapi/pkm/{h}`.")
        w("")
        groups = []
        for entry in cs:
            if not groups or groups[-1][0] != entry[4]:
                groups.append((entry[4], []))
            groups[-1][1].append(entry)
        for gname, rows in groups:
            has_note = any(r[3] for r in rows)
            head, body = shape_group(gname)
            if head:
                w("")
                w(f"*{head}.*")
            if body:
                w("")
                for chunk in textwrap.wrap(body, 72):
                    w(chunk)
            w("")
            w("| Constant | Value |" + (" Notes |" if has_note else ""))
            w("|---|---|" + ("---|" if has_note else ""))
            for name, args, raw, comment, _ in rows:
                val = (f"`{raw.replace('|', chr(92) + '|')}`" if args
                       else fmt_value(name, raw, values.get(name, 0)))
                disp = f"`{name}{args}`" if args else f"`{name}`"
                note = comment.replace("|", "\\|")
                w(f"| {disp} | {val} |" + (f" {note} |" if has_note else ""))
        w("")

    text = "\n".join(o).rstrip() + "\n"
    text = re.sub(r"\n{3,}", "\n\n", text)
    if check:
        cur = OUT.read_text() if OUT.exists() else ""
        if cur != text:
            print(f"{OUT} is out of date; regenerate with gen-kacs-abi.py", file=sys.stderr)
            return 1
        print("up to date")
        return 0
    OUT.write_text(text)
    print(f"wrote {OUT} ({len(text.splitlines())} lines)")
    return 0


sys.exit(main())
