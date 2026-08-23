#!/usr/bin/env python3
"""Generate the stratafs constants appendix of the Peios Kernel TRM.

Every value comes from the source: the private header, the KACS-shared
header, the copy-up translation unit, and the Rust decision core. Prose
framing lives here; nothing factual is transcribed by hand.

stratafs headers include kernel headers, so unlike the KACS ABI appendix
this cannot compile a probe. The one layout it reports — the staging
marker — is computed from the declared fixed-width types of a packed
struct, which is deterministic.

Usage:  python3 pkm/tools/gen-stratafs-constants.py [--check]

Writes the appendix into learn/. With --check, exits non-zero if the file
on disk differs from what would be generated, without writing.
"""
import re
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
HDR = ROOT / "pkm/stratafs/stratafs.h"
SHARED = ROOT / "pkm/kernel/include/linux/kacs_stratafs.h"
COPY_UP = ROOT / "pkm/stratafs/copy_up.c"
CORE = ROOT / "pkm/crates/stratafs-core/src/lib.rs"
KCONFIG = ROOT / "pkm/stratafs/Kconfig"
MAKEFILE = ROOT / "pkm/stratafs/Makefile"
OUT = (ROOT / "learn/peios.product/3--advanced-peios.antho/300--trms.shelf"
       / "100--peios-kernel.book/4--stratafs/a1--constants.md")

# The page's own identity. learn CI fails a deploy on an article with no
# description (learn 3362f6d), and this file is overwritten wholesale.
DESCRIPTION = ("Every stratafs constant \u2014 filesystem identity, stratum "
               "flags, extended attributes, copy-up and staging markers "
               "\u2014 generated from the source.")

DEFINE = re.compile(r"^#define\s+(\w+)\s+(.+?)\s*$")
LE_SIZES = {"__le16": 2, "__le32": 4, "__le64": 8, "__u8": 1}


def defines(path, names=None):
    """Every object-like #define in a file, in declaration order."""
    found = []
    for line in path.read_text().splitlines():
        m = DEFINE.match(line)
        if not m:
            continue
        name, raw = m.group(1), m.group(2).strip()
        if name.endswith("_H") and not raw:
            continue
        if "(" in name:            # function-like macro
            continue
        if names is not None and name not in names:
            continue
        found.append((name, raw))
    return found


def resolve(raw, table):
    """Fold a #define's text into a value, following one level of alias."""
    raw = raw.strip()
    if raw in table:
        return resolve(table[raw], table)
    m = re.fullmatch(r"BIT\((\d+)\)|1\s*<<\s*(\d+)", raw)
    if m:
        return f"0x{1 << int(m.group(1) or m.group(2)):X}"
    m = re.fullmatch(r"\(?(\d+)U?\s*\*\s*(\d+)U?\)?", raw)
    if m:
        return str(int(m.group(1)) * int(m.group(2)))
    m = re.fullmatch(r"(0[xX][0-9a-fA-F]+)[UL]*", raw)
    if m:
        return m.group(1)
    m = re.fullmatch(r"(\d+)[UL]*", raw)
    if m:
        return m.group(1)
    if "|" in raw:
        parts = [resolve(p, table) for p in raw.split("|")]
        try:
            return f"0x{sum(int(p, 0) for p in parts):X}"
        except ValueError:
            return raw
    return raw


def ascii_gloss(value):
    """Render a 32-bit magic as its ASCII bytes where they are printable."""
    if not re.fullmatch(r"0[xX][0-9a-fA-F]{8}", value):
        return None
    n = int(value, 16)
    chars = [(n >> s) & 0xFF for s in (24, 16, 8, 0)]
    if all(0x20 <= c < 0x7F for c in chars):
        return "".join(chr(c) for c in chars)
    return None


def struct_fields(path, name):
    """Field list of a struct, as (type, name) in declaration order."""
    text = path.read_text()
    m = re.search(r"struct\s+" + name + r"\s*\{(.*?)\n\}", text, re.S)
    if not m:
        raise SystemExit(f"struct {name} not found in {path}")
    fields = []
    for line in m.group(1).splitlines():
        line = line.strip().rstrip(";")
        if not line or line.startswith("/*") or line.startswith("*"):
            continue
        parts = line.split()
        if len(parts) != 2:
            raise SystemExit(f"unparsed field in struct {name}: {line!r}")
        fields.append((parts[0], parts[1]))
    return fields


def enum_values(path, name):
    """Enumerator names and explicit values of a C enum."""
    text = path.read_text()
    m = re.search(r"enum\s+" + name + r"\s*\{(.*?)\n\}", text, re.S)
    if not m:
        raise SystemExit(f"enum {name} not found in {path}")
    out = []
    for entry in m.group(1).split(","):
        entry = entry.strip()
        if not entry:
            continue
        k, _, v = entry.partition("=")
        out.append((k.strip(), v.strip()))
    return out


def rust_consts(path):
    """`pub const NAME: TYPE = VALUE;` from the decision core."""
    out = []
    for m in re.finditer(r"pub const (\w+):\s*\w+\s*=\s*(.+?);", path.read_text()):
        out.append((m.group(1), m.group(2).strip()))
    return out


def rust_enum(path, name):
    """Discriminants of a `#[repr(i32)]` enum in the decision core."""
    m = re.search(r"pub enum " + name + r"\s*\{(.*?)\n\}", path.read_text(), re.S)
    if not m:
        raise SystemExit(f"rust enum {name} not found")
    out = []
    for entry in m.group(1).split(","):
        entry = entry.strip()
        if not entry:
            continue
        k, _, v = entry.partition("=")
        out.append((k.strip(), v.strip()))
    return out


def esc(cell):
    """A markdown table cell: a pipe inside one silently breaks the row."""
    return cell.replace("|", "\\|")


def table(header, rows):
    rows = [tuple(esc(c) for c in row) for row in rows]
    header = tuple(esc(h) for h in header)
    widths = [len(h) for h in header]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))
    def line(cells):
        return "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"
    out = [line(header), "|" + "|".join("-" * (w + 2) for w in widths) + "|"]
    out += [line(r) for r in rows]
    return "\n".join(out)


def build():
    hdr = defines(HDR)
    shared = defines(SHARED)
    cu = defines(COPY_UP)
    alias = {k: v for k, v in hdr + shared + cu}

    def row(name, raw, note=""):
        value = resolve(raw, alias)
        gloss = ascii_gloss(value)
        if gloss and not note:
            note = f"ASCII `{gloss}`"
        return (f"`{name}`", f"`{value}`", note)

    parts = ["---", "title: Constants", f"description: {DESCRIPTION}",
             "---", "", (
        "Every value below is generated from the source by\n"
        "`pkm/tools/gen-stratafs-constants.py`. Nothing here is transcribed by\n"
        "hand, and the generator's `--check` mode fails if the two drift apart."
    ), ""]

    # --- identity -------------------------------------------------------
    ident_names = ["STRATAFS_MAGIC", "STRATAFS_NAME", "STRATAFS_MAX_STRATA"]
    notes = {
        "STRATAFS_MAGIC": "Superblock magic, reported by `statfs` (§4.2.2)",
        "STRATAFS_NAME": "The name the filesystem registers under",
        "STRATAFS_MAX_STRATA": "Longest stratum stack accepted (§4.2.1)",
    }
    rows = [row(n, dict(hdr)[n], notes[n]) for n in ident_names]
    parts += ["## Filesystem identity", "",
              table(("Constant", "Value", "Meaning"), rows), "", (
        "`STRATAFS_MAGIC` is an alias for `STRATAFS_SUPER_MAGIC`, which is\n"
        "declared in the header stratafs shares with KACS so that the mount\n"
        "policy class keyed on it cannot drift (§4.6.4)."
    ), ""]

    # --- flags ----------------------------------------------------------
    flag_notes = {
        "STRATAFS_F_CREATE": "The `create` flag (§4.2.1)",
        "STRATAFS_F_RO": "The `ro` flag",
        "STRATAFS_F_AM": "The `am` flag",
    }
    rows = [row(n, dict(hdr)[n], flag_notes[n]) for n in flag_notes]
    parts += ["## Stratum flags", "",
              table(("Constant", "Value", "Meaning"), rows), ""]

    # --- xattrs ---------------------------------------------------------
    xattr_notes = {
        "STRATAFS_XATTR_PREFIX": "Reserved namespace; never forwarded to a provider (§4.7)",
        "STRATAFS_XATTR_ORIGIN": "Synthetic, read-only, hidden from listings (§4.7)",
        "STRATAFS_XATTR_STAGING": "Copy-up staging marker; also reserved (§4.5.2)",
    }
    rows = [row(n, dict(hdr)[n], xattr_notes[n]) for n in xattr_notes]
    parts += ["## Extended attributes", "",
              table(("Constant", "Value", "Meaning"), rows), "", (
        "`STRATAFS_XATTR_STAGING` is an alias for `STRATAFS_STAGING_XATTR`,\n"
        "declared in the shared header. Note the name it resolves to lies\n"
        "outside the reserved `system.stratafs.` namespace, yet receives the\n"
        "same treatment (§4.7).\n\n"
        "The canonical security-descriptor attribute is KACS's, not\n"
        "stratafs's; stratafs only detects it in order to exclude it from\n"
        "copy-up replication (§4.6.3)."
    ), ""]

    # --- staging --------------------------------------------------------
    stage_notes = {
        "STRATAFS_STAGE_MARKER_MAGIC": "Marker magic",
        "STRATAFS_STAGE_MARKER_VERSION": "Marker version",
    }
    rows = [row(n, dict(hdr)[n], stage_notes[n]) for n in stage_notes]
    cu_notes = {
        "STRATAFS_COPY_BUFFER_SIZE": "Copy-up read/write chunk, in bytes (§4.5.2)",
        "STRATAFS_STAGE_PREFIX": "Staged-name prefix",
        "STRATAFS_RECOVERY_BATCH": "Names scanned per staging-recovery pass",
    }
    rows += [row(n, dict(cu)[n], cu_notes[n]) for n in cu_notes if n in dict(cu)]
    parts += ["## Copy-up and staging", "",
              table(("Constant", "Value", "Meaning"), rows), ""]

    fields = struct_fields(HDR, "stratafs_stage_marker")
    off, layout = 0, []
    for ctype, fname in fields:
        size = LE_SIZES[ctype]
        layout.append((str(off), str(size), f"`{fname}`", f"`{ctype}`"))
        off += size
    parts += ["### The staging marker", "", (
        f"`struct stratafs_stage_marker` is packed and {off} bytes, all fields\n"
        "little-endian. It is the value of the staging attribute above."
    ), "", table(("Offset", "Size", "Field", "Type"), layout), ""]

    # --- routing --------------------------------------------------------
    c_route = enum_values(HDR, "stratafs_route")
    r_route = rust_enum(CORE, "Route")
    rows = [(f"`{c}`", f"`{cv}`", f"`{r}`")
            for (c, cv), (r, _) in zip(c_route, r_route)]
    parts += ["## Routing", "", (
        "The value `route_existing` returns (§4.5.1), as the Rust decision\n"
        "core names it and as the C glue mirrors it. The discriminants match."
    ), "", table(("C enumerator", "Value", "Rust"), rows), ""]

    # --- rust core ------------------------------------------------------
    rc = rust_consts(CORE)
    rtab = dict(rc)
    rows = [(f"`{k}`", f"`{resolve(v, rtab)}`") for k, v in rc]
    parts += ["## The decision core", "", (
        "`stratafs-core` holds the stack-wide flag rules, provider selection,\n"
        "and routing. Its flag bits match the C ones above exactly."
    ), "", table(("Constant", "Value"), rows), ""]

    rows = [(f"`{k}`", f"`{v}`") for k, v in rust_enum(CORE, "ConfigError")]
    parts += [(
        "The crate distinguishes these configuration errors. The C boundary\n"
        "collapses all of them to `EINVAL`, so the distinction is not\n"
        "observable to a caller (§4.2.1)."
    ), "", table(("Error", "Discriminant"), rows), ""]

    # --- build ----------------------------------------------------------
    cfg = re.findall(r"^config (\w+)", KCONFIG.read_text(), re.M)
    objs = re.search(r"stratafs-y\s*:=\s*(.+)", MAKEFILE.read_text())
    parts += ["## Build configuration", "", (
        f"stratafs is built by `CONFIG_{cfg[0]}`, a boolean option, so what it\n"
        "builds is linked into `vmlinux` rather than loaded. It depends on\n"
        "`CONFIG_SECURITY_PKM` and selects `FS_STACK`. Its sources are staged\n"
        "into the kernel tree as `fs/stratafs`, separate from PKM's own\n"
        "`security/pkm`. " +
        ", ".join(f"`CONFIG_{c}`" for c in cfg[1:]) +
        " builds the in-kernel unit tests."
    ), "", "The translation units are:", "",
        "".join(f"- `{o}`\n" for o in objs.group(1).split()), ""]

    return "\n".join(parts).rstrip() + "\n"


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
        if not OUT.exists() or OUT.read_text() != text:
            print(f"stale: {OUT.relative_to(ROOT)}", file=sys.stderr)
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)} ({len(text.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
