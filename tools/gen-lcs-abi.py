#!/usr/bin/env python3
"""Generate the LCS ABI appendix of the Peios Kernel TRM from pkm/uapi/pkm/lcs.h.

Constant values, ioctl encodings and struct layouts are obtained by compiling a
probe against the real headers, so the output cannot drift from the ABI.

This file owns the appendix outright and overwrites it wholesale. Nothing
hand-written may live there: prose about the ABI belongs in the notes
appendix beside it, which no generator writes.

Usage:  python3 pkm/tools/gen-lcs-abi.py [--check]

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
HDR = UAPI / "pkm" / "lcs.h"
TRACE_H = UAPI / "pkm" / "trace.h"
SYSCALL_H = UAPI / "pkm" / "syscall.h"
LCS_SRC = ROOT / "pkm" / "lcs"
OUT = (ROOT / "learn/peios.product/3--advanced-peios.antho/300--trms.shelf"
       / "100--peios-kernel.book/5--lcs/a1--lcs-abi.md")

# The page's own identity, not prose about the ABI. learn CI fails a deploy
# on an article with no description (learn 3362f6d), so it is emitted here
# rather than left in a file the generator overwrites wholesale.
DESCRIPTION = ("Every LCS syscall number, ioctl, structure layout and "
               "constant, generated from the uapi headers and measured by "
               "compilation.")

DEFINE = re.compile(r"^#define\s+([A-Z_][A-Z0-9_]*)(\([^)]*\))?\s+(.+?)\s*$")
TRAILING = re.compile(r"/\*\s*(.*?)\s*\*/")
# The header cites the PSD series, which this manual replaces. Drop those
# citations rather than emit stale cross-references into the TRM.
PSD_REF = re.compile(r"(?:See\s+)?PSD-\d+(?:\s*§[\d.]+)?[,;:]?\s*", re.I)

# Named-citation anchors for the stable constant groups, keyed by the leading
# words of each group's heading comment in the header (case-insensitive,
# after the PSD reference is stripped). One anchor names one group: the unit
# a test cites is the group. A retitled group silently drops its anchor -- the
# learn build then surfaces any test left pointing at the retired name -- and
# a group not listed here carries none.
GROUP_ANCHORS = [
    ("syscall and ioctl argument sizes", "lcs-abi.argument-sizes"),
    ("transaction state codes", "lcs-abi.txn-state-codes"),
    ("syscall flags and dispositions", "lcs-abi.syscall-flags-and-dispositions"),
    ("registry key access rights", "lcs-abi.key-access-rights"),
    ("security information flags", "lcs-abi.security-information-flags"),
    ("registry value types", "lcs-abi.value-types"),
    ("watch event types and filters", "lcs-abi.watch-event-types-and-filters"),
    ("watch event raw byte layout", "lcs-abi.watch-record-layout"),
    ("rsi common wire layout", "lcs-abi.rsi-wire-layout"),
    ("rsi op codes and response op codes", "lcs-abi.rsi-op-codes"),
    ("rsi status codes", "lcs-abi.rsi-status-codes"),
    ("rsi path target types", "lcs-abi.rsi-path-target-types"),
    ("rsi_write_key field mask bits", "lcs-abi.rsi-write-key-field-mask"),
    ("rsi transaction modes and source-registration flags",
     "lcs-abi.rsi-txn-modes-and-registration-flags"),
    ("backup record types and magic", "lcs-abi.backup-record-types"),
    # trace.h
    ("lcs_rsi_request op", "lcs-abi.trace.rsi-request-ops"),
    ("lcs_rsi_response reason", "lcs-abi.trace.rsi-response-reasons"),
    ("lcs_source_fd reason", "lcs-abi.trace.source-fd-reasons"),
    ("lcs_in_flight reason", "lcs-abi.trace.in-flight-reasons"),
    ("lcs_route op", "lcs-abi.trace.route-ops"),
    ("lcs_registration decision", "lcs-abi.trace.registration-decisions"),
    ("lcs_bootstrap stage", "lcs-abi.trace.bootstrap-stages"),
    ("lcs_runtime_limits field_id", "lcs-abi.trace.runtime-limit-fields"),
    ("lcs_audit event_type_id", "lcs-abi.trace.audit-event-types"),
    ("lcs_txn state", "lcs-abi.trace.txn-states"),
    ("lcs_key_fd cmd", "lcs-abi.trace.key-fd-cmds"),
]


def group_anchor(text):
    """The named-citation anchor for a constant group, or None."""
    key = re.sub(r"\s+", " ", PSD_REF.sub("", text or "")).strip().lower()
    return next((n for k, n in GROUP_ANCHORS if key.startswith(k)), None)


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


def parse_header(path):
    """Return (constants, structs). constants: [(name, args, raw, comment, group)]."""
    lines = join_continuations(path.read_text().splitlines())
    consts, group, pending = [], None, None
    for line in lines:
        s = line.strip()
        if s.startswith("/*"):
            pending = [s.lstrip("/* ").rstrip("*/ ").strip()]
            if s.endswith("*/"):
                group = " ".join(x for x in pending if x).strip()
                pending = None
            continue
        if pending is not None:
            pending.append(s.lstrip("* ").rstrip("*/ ").strip())
            if s.endswith("*/"):
                group = " ".join(x for x in pending if x).strip()
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
    for c in sorted(LCS_SRC.glob("*.c")):
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


def glibc_syscall_alias(name):
    """The standard lowercase SYS_* spelling exported by Peios glibc."""
    return "SYS_" + name.removeprefix("SYS_").lower()


def probe(consts, structs, syscall_consts):
    """Compile a probe to resolve constant values, ioctl encodings and layouts."""
    src = ['#include <stdio.h>', '#include <stddef.h>', '#include <stdint.h>',
           '#include <pkm/lcs.h>', '#include <pkm/syscall.h>',
           '#include <pkm/trace.h>', "int main(void){"]
    numeric = []
    for name, args, raw, _, _ in consts + syscall_consts:
        if args or raw.startswith('"'):
            continue
        numeric.append(name)
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
    if stripped.startswith("_io") or "|" in raw:
        return f"`0x{val:08X}`"
    return f"`{val}`"


def table(head, rows):
    """Render a markdown table, escaping pipes in every cell."""
    o = ["| " + " | ".join(esc(h) for h in head) + " |",
         "|" + "|".join("---" for _ in head) + "|"]
    for r in rows:
        o.append("| " + " | ".join(esc(str(c)) for c in r) + " |")
    return o


IOC_DIR = {0: "_IO", 1: "_IOW", 2: "_IOR", 3: "_IOWR"}


def ioc_decode(val):
    """Split a _IOC-encoded number into its direction, number and size.

    Linux packs these as (dir << 30) | (size << 16) | (type << 8) | nr, so the
    ioctl number is the low byte and the type byte sits above it.
    """
    return IOC_DIR[(val >> 30) & 3], val & 0xFF, (val >> 16) & 0x3FFF


def build():
    consts, structs = parse_header(HDR)
    syscall_consts = [c for c in parse_header(SYSCALL_H)[0]
                      if c[0].startswith("SYS_REG_")]
    # trace.h is the single source of truth for the kacs:, kmes: and lcs:
    # tracepoint codes alike. Only the LCS ones belong here; the KACS ones are
    # generated into the KACS ABI appendix by gen-kacs-abi.py.
    trace_consts = [c for c in parse_header(TRACE_H)[0]
                    if c[0].startswith("LCS_")]
    values, sizes, offsets = probe(consts + trace_consts, structs,
                                   syscall_consts)
    by_name = {c[0]: c for c in consts}
    o = []
    w = o.append

    w("---")
    w("title: LCS ABI Reference")
    w(f"description: {DESCRIPTION}")
    w("---")
    w("")
    w("Every name, value, offset and size in this appendix is generated from")
    w("`pkm/uapi/pkm/lcs.h` by `pkm/tools/gen-lcs-abi.py`, with ioctl")
    w("encodings and struct layouts measured by compiling a probe against the")
    w("real header. Regenerate it whenever the ABI changes; do not edit it by")
    w("hand. The names here are the ones a program actually compiles against."
      " [*lcs-abi.generated-from-source]")
    w("")
    w("What a compiler cannot measure -- which properties belong with their")
    w("operations rather than here, and the kernel configuration -- is in the")
    w("notes appendix, §5.B, which this generator does not touch.")
    w("")

    # --- syscalls -------------------------------------------------------
    w("## Syscall numbers [*lcs-abi.syscall-numbers]")
    w("")
    w("Signatures are read from the `SYSCALL_DEFINE` sites in `pkm/lcs/`.")
    w("The PKM UAPI exports the uppercase constants in `<pkm/syscall.h>`. Peios")
    w("glibc 2.44-5 and later exports the standard lowercase `SYS_reg_*`")
    w("aliases in `<sys/syscall.h>`; each alias has the same number as its PKM")
    w("constant.")
    w("")
    sigs = syscall_signatures()
    rows = []
    for name, _, _, _, _ in syscall_consts:
        fn = name.replace("SYS_", "").lower()
        sig = sigs.get(fn)
        rows.append([values[name], f"`{name}`", f"`{glibc_syscall_alias(name)}`",
                     f"`{fn}({sig})`" if sig else ""])
    o += table(["Number", "PKM constant", "glibc alias", "Signature"],
               sorted(rows))
    w("")

    # --- ioctls ---------------------------------------------------------
    w("## Ioctls [*lcs-abi.ioctl-numbers]")
    w("")
    w("The type byte is `'R'`. Ioctl number namespaces are per fd type, so")
    w("`REG_SRC_REGISTER` (number 0 on the source device) and")
    w("`REG_IOC_QUERY_VALUE` (number 0 on a key fd) do not collide: the")
    w("kernel dispatches on the fd's `file_operations`, not globally. The")
    w("encoded value is what `_IOC` produces from the direction, type byte,")
    w("number and argument size.")
    w("")
    groups = [("Source device fd", ["REG_SRC_REGISTER"]),
              ("Key fd", [n for n, _, _, _, _ in consts
                          if n.startswith("REG_IOC_") and not n.endswith("_NR")
                          and n not in ("REG_IOC_TYPE", "REG_IOC_COMMIT",
                                        "REG_IOC_TXN_STATUS")]),
              ("Transaction fd", ["REG_IOC_COMMIT", "REG_IOC_TXN_STATUS"])]
    for title, names in groups:
        w(f"*{title}.*")
        w("")
        rows = []
        for n in names:
            if n not in values:
                continue
            direction, number, size = ioc_decode(values[n])
            raw = by_name[n][2]
            m = re.search(r"struct\s+(\w+)", raw)
            arg = f"`struct {m.group(1)}`" if m else "none"
            rows.append([f"`{n}`", number, direction, arg, size,
                         f"`0x{values[n]:08X}`"])
        o += table(["Ioctl", "Number", "Direction", "Argument", "Arg size",
                    "Encoded"], rows)
        w("")

    # --- structures -----------------------------------------------------
    w("## Structure layouts")
    w("")
    w("Offsets and sizes are measured, not declared. The header also defines")
    w("a `_SIZE` constant for each of these structures; the two agree by")
    w("construction, and a mismatch fails the build in `uapi/smoke_test.c`.")
    w("")
    for sname, fields in structs:
        if sname not in sizes:
            continue
        w(f"### `struct {sname}` [*lcs-abi.struct-{sname.replace('_', '-')}]")
        w("")
        w(f"Total size {sizes[sname]} bytes.")
        w("")
        fo = {f[0]: f for f in offsets.get(sname, [])}
        rows = []
        for ctype, fname, arr in fields:
            if fname not in fo:
                continue
            _, off, sz = fo[fname]
            disp = f"`{ctype}`" + (f"`[{arr}]`" if arr else "")
            rows.append([off, sz, disp, f"`{fname}`"])
        o += table(["Offset", "Size", "Type", "Field"], rows)
        w("")

    # --- grouped constants ----------------------------------------------
    skip_groups = {
        "Registry ioctl type byte.",
        "Source registration ioctl number namespace.",
        "Key-fd and transaction-fd ioctl number namespace.",
        "Source registration ioctl.",
        "Key-fd ioctls.",
        "Transaction-fd ioctls.",
    }
    seen = set()
    order = []
    for name, args, raw, comment, group in consts:
        if group in skip_groups or name in ("REG_IOC_TYPE",):
            continue
        if name.endswith("_NR"):
            continue
        # An ioctl macro is already in the ioctl table above, whatever comment
        # group it fell into; the _IOWR note over REG_IOC_QUERY_KEY_INFO used
        # to open a group of its own and list nine ioctls a second time.
        if re.match(r"_IOW?R?\s*\(", raw.strip()):
            continue
        if group not in seen:
            seen.add(group)
            order.append((group, []))
        for g, rows in order:
            if g == group:
                rows.append((name, args, raw, comment))
                break

    w("## Constants")
    w("")
    w("Grouped as the header groups them.")
    w("")
    for group, rows in order:
        if not rows:
            continue
        head = PSD_REF.sub("", group or "").strip().rstrip(".")
        if head:
            head = head[0].upper() + head[1:]
        anchor = group_anchor(group)
        cite = f" [*{anchor}]" if anchor else ""
        if head:
            w(f"*{head}.*{cite}")
            w("")
        has_note = any(r[3] for r in rows)
        trows = []
        for name, args, raw, comment in rows:
            if raw.startswith('"'):
                val = f"`{raw}`"
            elif name in values:
                val = fmt_value(raw, values[name])
            else:
                val = f"`{raw}`"
            note = PSD_REF.sub("", comment).strip()
            trows.append([f"`{name}`", val] + ([note] if has_note else []))
        o += table(["Constant", "Value"] + (["Notes"] if has_note else []), trows)
        w("")

    if trace_consts:
        w("## Tracepoint diagnostic codes")
        w("")
        w("From `uapi/pkm/trace.h`. These are a diagnostic contract for")
        w("ftrace, perf and eBPF consumers, letting a tool decode an `lcs:`")
        w("event's `reason`, `op` or `state` field without recompiling")
        w("against a specific kernel. No LCS syscall accepts or returns")
        w("them, and values are append-only.")
        w("")
        groups = []
        for entry in trace_consts:
            if not groups or groups[-1][0] != entry[4]:
                groups.append((entry[4], []))
            groups[-1][1].append(entry)
        for group, rows in groups:
            # Not capitalised: these blocks open with the tracepoint's own
            # identifier, and title-casing turns lcs_rsi_request into
            # Lcs_rsi_request. Split into a short heading plus a wrapped body
            # the way the KACS appendix does, since several run to a paragraph.
            text = re.sub(r"\s+", " ", PSD_REF.sub("", group or "").strip())
            parts = re.split(r"(?<=\.)\s+", text, maxsplit=1)
            head = parts[0].rstrip(".")
            body = parts[1].strip() if len(parts) > 1 else ""
            if len(head) > 90:
                head, body = "", text
            anchor = group_anchor(group)
            cite = f" [*{anchor}]" if anchor else ""
            if head:
                w(f"*{head}.*{cite}")
                cite = ""
                w("")
            if body:
                chunks = textwrap.wrap(body, 72)
                # A group with no short heading has nothing to hang the
                # anchor on but the prose, so it rides the last line of it.
                if cite and chunks:
                    chunks[-1] += cite
                for chunk in chunks:
                    w(chunk)
                w("")
            has_note = any(r[3] for r in rows)
            trows = []
            for name, args, raw, comment, _ in rows:
                val = (fmt_value(raw, values[name]) if name in values
                       else f"`{raw}`")
                note = PSD_REF.sub("", comment).strip()
                trows.append([f"`{name}`", val] + ([note] if has_note else []))
            o += table(["Constant", "Value"] + (["Notes"] if has_note else []),
                       trows)
            w("")

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
            print(f"{OUT} is out of date; regenerate with gen-lcs-abi.py",
                  file=sys.stderr)
            return 1
        print("up to date")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(f"wrote {OUT} ({len(text.splitlines())} lines)")
    return 0


sys.exit(main())
