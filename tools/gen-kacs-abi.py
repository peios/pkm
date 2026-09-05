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
KACS_HEADERS = ["syscall.h", "token.h", "socket.h", "ipc.h", "access.h",
                "file.h", "process.h", "psb.h", "sd.h", "sid.h", "trace.h"]

# The page's own identity, not prose about the ABI. learn CI fails a deploy
# on an article with no description (learn 3362f6d), so this cannot be left
# to whoever last edited the file: the generator overwrites it wholesale.
DESCRIPTION = ("Every KACS syscall number, structure layout, constant and "
               "enumeration, generated from the uapi headers and measured by "
               "compilation.")

# Named-citation anchors for the stable constant groups, keyed by the leading
# words of each group's heading comment in the header. One anchor names one
# table, not one row: the rows are measured by compilation, so what a test
# cites is the group. A retitled group silently drops its anchor -- the learn
# build's citation grep is what surfaces a test left pointing at a retired
# name -- and a group not listed here carries none. Keys are matched in order
# against the group comment with its whitespace collapsed, so a key must be a
# prefix of exactly one group and must not be a prefix of an earlier one.
GROUP_ANCHORS = [
    # token.h
    ("kacs_open_self_token (SYS_KACS_OPEN_SELF_TOKEN) flags",
     "kacs-abi.open-self-token-flags"),
    ("Per-handle token rights", "kacs-abi.token-access-rights"),
    ("Token ioctl interface identifier", "kacs-abi.token-ioctl-magic"),
    ("kacs_priv_entry.attributes bits", "kacs-abi.privilege-attributes"),
    ("kacs_adjust_privs bulk-reset flag",
     "kacs-abi.privilege-reset-all-defaults"),
    ("kacs_restrict_args.flags bits", "kacs-abi.restrict-flags"),
    ("Token type (KACS_TOKEN_CLASS_TYPE)", "kacs-abi.token-types"),
    ("Impersonation level (KACS_TOKEN_CLASS_IMPERSONATION_LEVEL)",
     "kacs-abi.impersonation-levels"),
    ("Elevation type (KACS_TOKEN_CLASS_ELEVATION_TYPE)",
     "kacs-abi.elevation-types"),
    ("Mandatory-policy bits (KACS_TOKEN_CLASS_MANDATORY_POLICY)",
     "kacs-abi.mandatory-policy-bits"),
    ("Per-token audit-policy bits", "kacs-abi.audit-policy-bits"),
    ("Logon type (KACS_TOKEN_CLASS_LOGON_TYPE)", "kacs-abi.logon-types"),
    ("Maximum number of groups a token may carry",
     "kacs-abi.token-max-groups"),
    ("Number of 64-bit words in a group enabled-state bitmask",
     "kacs-abi.token-group-mask-words"),
    ("kacs_create_token (SYS_KACS_CREATE_TOKEN) spec wire format",
     "kacs-abi.token-spec-wire-format"),
    ("Byte offsets of the fixed token-spec header fields",
     "kacs-abi.token-spec-offsets"),
    ("Byte length of the fixed token-source-name field",
     "kacs-abi.token-source-name-bytes"),
    ("Optional LCS registry-credentials extension",
     "kacs-abi.token-lcs-extension"),
    ("Byte offsets of the fixed LCS-extension header fields",
     "kacs-abi.token-lcs-extension-offsets"),
    ("kacs_create_logon_session (SYS_KACS_CREATE_LOGON_SESSION) spec wire",
     "kacs-abi.logon-session-spec-wire-format"),
    ("Byte offsets of the fixed-position session-spec fields",
     "kacs-abi.logon-session-spec-offsets"),
    ("Token-handle ioctls", "kacs-abi.token-ioctls"),
    ("Token information classes", "kacs-abi.token-information-classes"),
    ("Privileges, as single-bit masks", "kacs-abi.privilege-bits"),
    # socket.h
    ("KACS socket options", "kacs-abi.sol-kacs"),
    ("getsockopt only.", "kacs-abi.so-peer-token"),
    ("getsockopt / setsockopt. optval: __u32",
     "kacs-abi.so-impersonation-level"),
    ("getsockopt / setsockopt. optval: int", "kacs-abi.so-pass-token"),
    ("setsockopt only.", "kacs-abi.so-restamp"),
    ("Ancillary message type", "kacs-abi.scm-token"),
    # ipc.h
    ("KACS access rights for System V IPC objects",
     "kacs-abi.ipc-access-rights"),
    ("ipcctl gates:", "kacs-abi.sysv-sd-selectors"),
    # access.h
    ("Full size of kacs_access_check_args",
     "kacs-abi.access-check-args-size"),
    ("Minimum caller_size the kernel accepts",
     "kacs-abi.access-check-args-v1-size"),
    ("Byte size of one kacs_object_type_entry",
     "kacs-abi.object-type-entry-size"),
    ("Largest object-audit-context buffer",
     "kacs-abi.max-audit-context-len"),
    ("Largest @Local claims blob", "kacs-abi.max-local-claims-len"),
    ("Largest object-type tree entry count",
     "kacs-abi.max-object-type-count"),
    ("Claim value types", "kacs-abi.claim-value-types"),
    ("Claim attribute flags", "kacs-abi.claim-attribute-flags"),
    ("Central Access Policy (CAAP) spec wire format",
     "kacs-abi.caap-spec-wire-format"),
    ("Byte offsets of the fixed CAAP-spec prefix fields",
     "kacs-abi.caap-spec-offsets"),
    ("Byte length of the fixed CAAP-spec prefix",
     "kacs-abi.caap-spec-prefix-bytes"),
    # file.h
    ("Minimum caller-supplied size accepted", "kacs-abi.arg-block-min-sizes"),
    ("Create dispositions", "kacs-abi.create-dispositions"),
    ("Create options", "kacs-abi.create-options"),
    ("kacs_open_how.flags bits", "kacs-abi.open-how-flags"),
    ("File and directory object-specific access rights",
     "kacs-abi.file-access-rights"),
    ("Mount-policy values", "kacs-abi.mount-policy-values"),
    ("Status word kacs_open writes back", "kacs-abi.open-status-values"),
    # process.h
    ("KACS process object-specific access rights",
     "kacs-abi.process-access-rights"),
    # psb.h
    ("Process Security Block (PSB) process-mitigation bits",
     "kacs-abi.mitigation-bits"),
    ("All valid mitigation bits", "kacs-abi.mitigation-all-mask"),
    # sd.h
    ("Byte length of the self-relative security-descriptor header",
     "kacs-abi.sd-header-bytes"),
    ("SECURITY_INFORMATION selector bits",
     "kacs-abi.security-information-bits"),
    ("SECURITY_DESCRIPTOR_CONTROL bits", "kacs-abi.sd-control-bits"),
    ("Access-mask bits", "kacs-abi.standard-and-generic-rights"),
    ("ACE types", "kacs-abi.ace-types"),
    ("ACE header `ace_flags` byte", "kacs-abi.ace-flags"),
    ("Mandatory-label policy bits", "kacs-abi.mandatory-label-policy-bits"),
    ("Object-ACE body `Flags` field", "kacs-abi.object-ace-flags"),
    # sid.h
    ("Largest sub_authority_count", "kacs-abi.sid-max-sub-authorities"),
    ("Encoded byte length of a SID", "kacs-abi.sid-byte-len"),
    ("SID_AND_ATTRIBUTES", "kacs-abi.sid-attribute-bits"),
    # trace.h
    ("kacs_access_decision reason", "kacs-abi.trace.access-decision-reasons"),
    ("kacs_sd_cache reason", "kacs-abi.trace.sd-cache-reasons"),
    ("kacs_process_access reason", "kacs-abi.trace.process-access-reasons"),
    ("kacs_exec reason", "kacs-abi.trace.exec-reasons"),
    ("kacs_signing reason", "kacs-abi.trace.signing-reasons"),
    ("kacs_firmware reason", "kacs-abi.trace.firmware-reasons"),
    ("kacs_socket reason", "kacs-abi.trace.socket-reasons"),
    ("16 was KACS_SOCK_IMPERSONATE",
     "kacs-abi.trace.socket-reason-16-retired"),
    ("kacs_ipc reason", "kacs-abi.trace.ipc-reasons"),
    ("kacs_namespace stage", "kacs-abi.trace.namespace-stages"),
    ("kacs_psb reason", "kacs-abi.trace.psb-reasons"),
    ("kacs_token_ioctl cmd", "kacs-abi.trace.token-ioctl-cmds"),
    ("kacs_token_ref reason", "kacs-abi.trace.token-ref-reasons"),
    ("kacs_logon_session reason", "kacs-abi.trace.logon-session-reasons"),
    ("kacs_cred reason", "kacs-abi.trace.cred-reasons"),
    ("kacs_setid reason", "kacs-abi.trace.setid-reasons"),
    ("kacs_task reason", "kacs-abi.trace.task-reasons"),
    ("kacs_primary_install reason",
     "kacs-abi.trace.primary-install-reasons"),
    ("kacs_process_token_open reason",
     "kacs-abi.trace.process-token-open-reasons"),
    ("kacs_process_state reason", "kacs-abi.trace.process-state-reasons"),
    ("kacs_mount_policy reason", "kacs-abi.trace.mount-policy-reasons"),
    ("kacs_sd_syscall target_kind",
     "kacs-abi.trace.sd-syscall-target-kinds"),
    ("kacs_sd_syscall reason", "kacs-abi.trace.sd-syscall-reasons"),
    ("kacs_access_check reason", "kacs-abi.trace.access-check-reasons"),
    ("kacs_file_snapshot op", "kacs-abi.trace.file-snapshot-ops"),
    ("kacs_file_snapshot reason", "kacs-abi.trace.file-snapshot-reasons"),
    ("kacs_metadata reason", "kacs-abi.trace.metadata-reasons"),
    ("kacs_native_open_ext reason",
     "kacs-abi.trace.native-open-ext-reasons"),
    ("kacs_object reason", "kacs-abi.trace.object-reasons"),
    ("kacs_securityfs reason", "kacs-abi.trace.securityfs-reasons"),
    ("kacs_caap reason", "kacs-abi.trace.caap-reasons"),
    ("kacs_capability reason", "kacs-abi.trace.capability-reasons"),
    ("kacs_privilege reason", "kacs-abi.trace.privilege-reasons"),
    ("kacs_tlp reason", "kacs-abi.trace.tlp-reasons"),
]


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


def group_anchor(text):
    """The named-citation anchor for a constant group, or None.

    Keyed on the group's own comment rather than on the italic heading
    shape_group derives from it, because a group whose comment opens with a
    long sentence gets no heading at all and would otherwise be uncitable --
    and several of those (the privilege bits, the CAAP spec, the
    SECURITY_INFORMATION selectors) are exactly what a test wants to name.
    """
    key = re.sub(r"\s+", " ", PSD_REF.sub("", text or "")).strip()
    return next((n for k, n in GROUP_ANCHORS if key.startswith(k)), None)


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
    w("The names here are the ones a program actually compiles against."
      " [*kacs-abi.generated-from-source]")
    w("Everything about the ABI a compiler cannot measure -- token query")
    w("payload shapes, the specification spellings that differ from these")
    w("names, what is documented elsewhere, and the kernel configuration")
    w("-- is in the notes appendix, §3.D, which this generator does not")
    w("touch.")
    w("")

    # --- syscalls
    w("## Syscall numbers [*kacs-abi.syscall-numbers]")
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
        w(f"{lo}\u2013{hi}, documented in their own chapters."
          " [*kacs-abi.sibling-syscall-range]")
        w("")

    # --- structs
    w("## Structure layouts")
    w("")
    for sname, fields in structs:
        if sname not in sizes:
            continue
        w(f"### `struct {sname}` [*kacs-abi.struct-{sname.replace('_', '-')}]")
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
        "trace.h": "Tracepoint diagnostic codes",
    }
    for h in KACS_HEADERS:
        if h == "syscall.h":
            continue
        cs = [c for c in per_header[h][0]]
        # trace.h is the single source of truth for the kacs:, kmes: and lcs:
        # tracepoint codes alike. Only the KACS ones belong in the KACS ABI
        # appendix; the others need homes in their own subsystems' references.
        if h == "trace.h":
            cs = [c for c in cs if c[0].startswith("KACS_")]
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
            anchor = group_anchor(gname)
            cite = f" [*{anchor}]" if anchor else ""
            if head:
                w("")
                w(f"*{head}.*{cite}")
                cite = ""
            if body:
                w("")
                chunks = textwrap.wrap(body, 72)
                # A group with no short heading has nothing to hang the
                # anchor on but the prose, so it rides the last line of it.
                if cite and chunks:
                    chunks[-1] += cite
                    cite = ""
                for chunk in chunks:
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
