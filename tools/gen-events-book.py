#!/usr/bin/env python3
"""Generate the Peios Events Index from the evman catalogue.

The catalogue is the `.evman` fragments (PGSS §6.10): the kernel's in
pkm/evman/, and each userspace component's at the root of its own
repository. Every event type, group and field the book lists comes from
them, so the book cannot drift from what the fragments define.

This file owns its pages outright and overwrites them wholesale:

  2--groups/             one page per group
  3--kacs/ .. 15--trustd/  one chapter per event-type root, one page per
                         event
  a1--all-event-types.md
  a2--field-index/       one page per field root

An owned directory holds nothing but what this writes; a page in it that
the catalogue no longer produces is deleted. Prose that is not generated
-- the introduction and the registry's watch records, which are not
events -- lives in the book's other pages, which this never touches.

Page slugs are the event name with each `.` replaced by `-`
(`kacs.audit.access.checked` -> `kacs-audit-access-checked`). Groups are
`group-<name>` and field roots `fields-<root>`, so that no generated slug
is a bare word another page might also use.

Usage:  python3 pkm/tools/gen-events-book.py [--check]

Writes the pages into learn/. With --check, exits non-zero if any owned
page on disk differs from what would be generated, or an owned directory
holds a page that would not be, without writing.
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
KERNEL_FRAGMENTS = ROOT / "pkm" / "evman"
# Userspace components ship their fragments from their own repositories.
# A checkout without one of them is legitimate; the book then lacks its
# fields, and says so on stderr.
USERSPACE_FRAGMENTS = [
    ROOT / "peinit" / "peinit.evman",
    ROOT / "peipkg" / "peipkg.evman",
    ROOT / "eventd" / "eventd.evman",
    ROOT / "authd" / "authd.evman",
    ROOT / "authd" / "lpsd.evman",
    ROOT / "timed" / "timed.evman",
    ROOT / "netd" / "netd.evman",
    ROOT / "trustd" / "trustd.evman",
]
BOOK = (ROOT / "learn/peios.product/2--using-peios.antho/600--reference.shelf"
        / "100--events.book")
TOOL = "pkm/tools/gen-events-book.py"

# The `~` reference prefix for a page in this book. Generated links always
# name the chapter too: a reference matches a contiguous tail of a page's
# slugs, so the chapter cannot be skipped.
BOOK_REF = "~peios/events"

# One chapter per event-type root, in book order. An event whose root is
# not listed stops the generator: placing a new root in the book is a
# decision, not something to guess. The kernel's roots come first, then
# userspace's. The book's hand-written chapter on the registry's watch
# records, which are not events, is numbered after the last of these.
CHAPTERS = [
    ("kacs", "3--kacs", "Access and Identity Events"),
    ("stratafs", "4--stratafs", "Filesystem Events"),
    ("lcs", "5--lcs", "Registry Events"),
    ("kmes", "6--kmes", "Event Stream Events"),
    ("ntfe", "7--ntfe", "Network Policy Events"),
    ("peinit", "8--peinit", "Service Events"),
    ("peipkg", "9--peipkg", "Package Events"),
    ("eventd", "10--eventd", "Event Store Events"),
    ("authd", "11--authd", "Authentication Events"),
    ("lpsd", "12--lpsd", "Local Principal Events"),
    ("timed", "13--timed", "Time Events"),
    ("netd", "14--netd", "Network Configuration Events"),
    ("trustd", "15--trustd", "Trust Events"),
]
GROUPS_DIR = "2--groups"
FIELD_INDEX_DIR = "a2--field-index"
ALL_TYPES = "a1--all-event-types.md"

OWNED_DIRS = [GROUPS_DIR, FIELD_INDEX_DIR] + [d for _, d, _ in CHAPTERS]
OWNED_FILES = [ALL_TYPES]

# The page's own identity. learn CI fails a deploy on an article with no
# description (learn 3362f6d), and every page here is overwritten
# wholesale, so each one's description is emitted here.
ALL_TYPES_DESCRIPTION = (
    "Every event type the evman catalogue defines, in one table: its "
    "tier, its defining fragment and its one-line summary, generated from "
    "the fragments.")


# --- the fragment parser -------------------------------------------------
#
# Follows peiosutils' libevman fragment.rs line for line, so that this
# reads a fragment exactly as `evman` does.

class Line:
    """A `field:` or `include:` line of an event record."""

    def __init__(self, kind, name, presence, n):
        self.kind = kind          # "field" or "include"
        self.name = name
        self.presence = presence  # required | optional | when ... | ""
        self.line = n
        self.values = None
        self.closed = None
        self.gloss_lines = []

    def gloss(self):
        return join_trimmed(self.gloss_lines)


class Record:
    def __init__(self, kind, name, n, fragment):
        self.kind = kind          # "field", "group" or "event"
        self.name = name
        self.line = n
        self.fragment = fragment  # the fragment's file name
        self.headers = {}         # first-seen order, later value wins
        self.includes = []        # a group's field paths
        self.lines = []           # an event's Lines
        self.prose = []

    def value(self, key):
        return self.headers.get(key)

    def body(self):
        return join_trimmed(self.prose)

    def summary(self):
        return first_sentence(self.body())


FIELD_LINE = re.compile(r"(field|include): (\S+)\s*(.*)$")
SUB_HEADER = re.compile(r"\s+(values|closed): (.*)$")


def parse(text, fragment):
    """Return (records, issues) for one fragment's text."""
    records, issues = [], []
    is_open = False
    state = "headers"
    for i, raw in enumerate(text.splitlines()):
        n = i + 1
        if raw.startswith("--- "):
            parts = raw[4:].split()
            if len(parts) == 2 and parts[0] in ("field", "group", "event"):
                records.append(Record(parts[0], parts[1], n, fragment))
                is_open = True
                state = "headers"
            else:
                issues.append((n, f"bad anchor: {raw!r}"))
                is_open = False
            continue
        if not records or not is_open:
            if raw.strip():
                issues.append((n, "text before any record"))
            continue
        rec = records[-1]

        if state == "headers":
            if not raw.strip():
                state = "prose"
            elif ":" in raw:
                key, value = raw.split(":", 1)
                # The group test is on the key as written, unstripped.
                if rec.kind == "group" and key == "include":
                    rec.includes.append(value.strip())
                else:
                    rec.headers[key.strip()] = value.strip()
            else:
                issues.append((n, f"bad header: {raw!r}"))
            continue

        if rec.kind == "event":
            m = FIELD_LINE.match(raw)
            if m:
                rec.lines.append(Line(m.group(1), m.group(2),
                                      m.group(3).strip(), n))
                state = "fields"
                continue

        if state == "fields":
            last = rec.lines[-1]
            if raw.startswith("  "):
                m = SUB_HEADER.match(raw)
                if m and m.group(1) == "values":
                    last.values = m.group(2).strip()
                elif m:
                    last.closed = m.group(2).strip()
                else:
                    last.gloss_lines.append(raw.strip())
            elif raw.strip():
                issues.append((n, "prose after the field lines"))
            elif last.gloss_lines:
                last.gloss_lines.append("")
            continue

        rec.prose.append(raw)
    return records, issues


def join_trimmed(lines):
    start = 0
    while start < len(lines) and not lines[start].strip():
        start += 1
    end = len(lines)
    while end > start and not lines[end - 1].strip():
        end -= 1
    return "\n".join(lines[start:end])


def first_sentence(body):
    """The first sentence of the first paragraph, on one line.

    A sentence ends at `.`, `?` or `!` followed by whitespace or the end of
    the paragraph; a dot inside a code span does not end one.
    """
    para = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            break
        para.append(line)
    para = " ".join(para)
    in_code = False
    for i, c in enumerate(para):
        if c == "`":
            in_code = not in_code
        elif c in ".?!" and not in_code and (
                i + 1 == len(para) or para[i + 1].isspace()):
            return para[:i + 1]
    return para


# --- the catalogue -------------------------------------------------------

class Catalogue:
    def __init__(self):
        self.fields = {}       # path -> Record
        self.groups = {}       # name -> Record
        self.events = {}       # name -> Record
        self.fragments = []    # file names, in read order
        self.problems = []     # (fragment, line, message)
        self.broken = set()    # fragments breaking rule 1, 2 or 3

    def problem(self, fragment, line, message, rule=None):
        self.problems.append((fragment, line, message))
        if rule in (1, 2, 3):
            self.broken.add(fragment)


def fragment_paths():
    """Every fragment to read, kernel first. Missing userspace ones are
    reported and skipped."""
    paths = sorted(KERNEL_FRAGMENTS.glob("*.evman"))
    for p in USERSPACE_FRAGMENTS:
        if p.exists():
            paths.append(p)
        else:
            print(f"skipped: no fragment at {p}", file=sys.stderr)
    return paths


def load():
    cat = Catalogue()
    tables = {"field": cat.fields, "group": cat.groups, "event": cat.events}
    for path in fragment_paths():
        name = path.name
        cat.fragments.append(name)
        records, issues = parse(path.read_text(), name)
        for n, msg in issues:
            cat.problem(name, n, msg)
        for rec in records:
            table = tables[rec.kind]
            if rec.name in table:
                first = table[rec.name]
                cat.problem(name, rec.line,
                            f"{rec.kind} {rec.name} already defined at "
                            f"{first.fragment}:{first.line}", rule=2)
                continue
            table[rec.name] = rec
    check(cat)
    return cat


def check(cat):
    """The §6.10 rules a display needs: what a link or an expansion would
    otherwise trip over. `evman lint` is the full check."""
    for g in cat.groups.values():
        for path in g.includes:
            if path not in cat.fields:
                cat.problem(g.fragment, g.line,
                            f"group {g.name} includes undefined field "
                            f"{path}", rule=1)
    for e in cat.events.values():
        if not e.value("tier"):
            cat.problem(e.fragment, e.line, f"event {e.name} has no tier")
        for ln in e.lines:
            known = cat.groups if ln.kind == "include" else cat.fields
            if ln.name not in known:
                cat.problem(e.fragment, ln.line,
                            f"event {e.name} names undefined {ln.kind} "
                            f"{ln.name}", rule=1)
    paths = sorted(cat.fields)
    for a, b in zip(paths, paths[1:]):
        if b.startswith(a + "."):
            rec = cat.fields[b]
            cat.problem(rec.fragment, rec.line,
                        f"{a} is defined as a value and as a map", rule=3)
    for rec in list(cat.fields.values()) + list(cat.groups.values()) \
            + list(cat.events.values()):
        texts = [rec.body()] + [ln.gloss() for ln in rec.lines]
        if any(BARE_SECTION.search(strip_code(t)) for t in texts):
            cat.problem(rec.fragment, rec.line,
                        f"{rec.kind} {rec.name}: a § reference names no "
                        "book directly before it, so a reader cannot tell "
                        "which document it cites")


# A book's short name, then a space or a line break, then the sign. md()
# keeps any § from linking into this book either way: see SECTION_SIGN.
BARE_SECTION = re.compile(r"(?<![A-Z]\s)§")


def strip_code(text):
    return re.sub(r"`[^`]*`", "", text)


# --- rendering helpers ---------------------------------------------------

CODE_SPAN = re.compile(r"`[^`]*`")

# Trail links a bare `§5.3` to section 5.3 of the book the page is in, and
# the PCSA books declare no inline_ref phrase, so even "PSPU §5.3" is a bare
# `§5.3` to it. In fragment prose that is never this book: it would link a
# citation of PSPU to whichever event page happens to be §5.3 here. The sign
# alone in an inline element is a text run of its own with no number after
# it, which trail leaves plain; the page reads the same.
SECTION_SIGN = "<span>§</span>"


def md(text):
    """Fragment prose as Markdown.

    §6.10 limits inline markup to **bold** and `code`, so every other
    character Markdown would act on is escaped: a lone `*`, brackets, and
    angle brackets. Code spans are left alone.

    A section sign is wrapped as SECTION_SIGN describes.
    """
    def esc_run(run):
        run = run.replace("\\", "\\\\")
        run = re.sub(r"(?<!\*)\*(?!\*)", r"\\*", run)
        run = run.replace("[", "\\[").replace("]", "\\]")
        run = run.replace("<", "&lt;").replace(">", "&gt;")
        return run.replace("§", SECTION_SIGN)

    out, pos = [], 0
    for m in CODE_SPAN.finditer(text):
        out.append(esc_run(text[pos:m.start()]))
        out.append(m.group(0))
        pos = m.end()
    out.append(esc_run(text[pos:]))
    return "".join(out)


def cell(text):
    """Markdown for one table cell: one line, paragraphs kept apart, and a
    pipe escaped even inside a code span (GFM splits cells first)."""
    paras = [re.sub(r"\s+", " ", p).strip()
             for p in re.split(r"\n\s*\n", text)]
    return "<br><br>".join(p for p in paras if p).replace("|", "\\|")


def table(head, rows):
    o = ["| " + " | ".join(head) + " |",
         "|" + "|".join("---" for _ in head) + "|"]
    for r in rows:
        o.append("| " + " | ".join(r) + " |")
    return o


def front(title, description):
    """Frontmatter. Both values are JSON strings, which YAML reads as
    double-quoted scalars, so a colon in a summary cannot break it."""
    plain = description.replace("`", "").replace("**", "")
    return ["---",
            f"title: {json.dumps(title, ensure_ascii=False)}",
            f"description: {json.dumps(plain, ensure_ascii=False)}",
            "---", ""]


def generated_note(source):
    return (f"*Generated from {source} by `{TOOL}`. Edit the fragment, not "
            "this page.*")


def split_values(values):
    return [v.strip() for v in values.split("|") if v.strip()]


def values_md(values):
    return " · ".join(f"`{v}`" for v in split_values(values))


def closed_word(closed):
    return {"true": "closed", "false": "open"}.get(closed, f"closed: {closed}")


def slug(name):
    return name.replace(".", "-")


def field_root(path):
    return path.split(".", 1)[0]


def chapter_of(event_name):
    root = event_name.split(".", 1)[0]
    for r, d, _ in CHAPTERS:
        if r == root:
            return d
    return None


def chapter_slug(dirname):
    return dirname.split("--", 1)[1]


def event_ref(name):
    return f"{BOOK_REF}/{chapter_slug(chapter_of(name))}/{slug(name)}"


def group_ref(name):
    return f"{BOOK_REF}/{chapter_slug(GROUPS_DIR)}/group-{name}"


def field_ref(path):
    return (f"{BOOK_REF}/{chapter_slug(FIELD_INDEX_DIR)}/"
            f"fields-{field_root(path)}#{path}")


def field_link(cat, path):
    if path in cat.fields:
        return f"[`{path}`]({field_ref(path)})"
    return f"`{path}`"


def event_link(name):
    return f"[`{name}`]({event_ref(name)})"


def group_link(cat, name):
    if name in cat.groups:
        return f"[`{name}`]({group_ref(name)})"
    return f"`{name}`"


def presence_md(presence):
    if presence.startswith("when "):
        return f"when `{presence[5:].strip()}`"
    return presence or "—"


def broken_warning(cat, fragment):
    if fragment not in cat.broken:
        return []
    found = [f"line {n}: {m}" for f, n, m in cat.problems if f == fragment]
    out = ["> [!WARNING]",
           f"> `{fragment}` breaks the catalogue rules that make a fragment "
           f"define anything (PGSS {SECTION_SIGN}6.10, rules 1 to 3). What "
           "it says is "
           "shown, but it is not in force:", ">"]
    out += [f"> - {md(x)}" for x in found]
    return out + [""]


# --- the reverse index ---------------------------------------------------

def carriers(cat):
    """path -> [(event name, group name or None)], every event carrying
    the field directly or through a group it includes."""
    by_path = {}
    for e in sorted(cat.events):
        for ln in cat.events[e].lines:
            if ln.kind == "field":
                by_path.setdefault(ln.name, []).append((e, None))
            elif ln.name in cat.groups:
                for p in cat.groups[ln.name].includes:
                    by_path.setdefault(p, []).append((e, ln.name))
    return by_path


def group_carriers(cat):
    by_group = {}
    for e in sorted(cat.events):
        for ln in cat.events[e].lines:
            if ln.kind == "include":
                by_group.setdefault(ln.name, []).append(e)
    return by_group


def member_of(cat):
    groups = {}
    for g in sorted(cat.groups):
        for p in cat.groups[g].includes:
            groups.setdefault(p, []).append(g)
    return groups


# --- pages ---------------------------------------------------------------

def event_page(cat, ev):
    o = front(ev.name, ev.summary())
    w = o.append
    o += broken_warning(cat, ev.fragment)
    w(f"- **Event type:** `{ev.name}`")
    w(f"- **Defined in:** `{ev.fragment}`")
    w(f"- **Tier:** {md(ev.value('tier') or 'not declared')}")
    w(f"- **Gating:** {md(ev.value('gating') or 'none declared')}")
    w(f"- **Cardinality:** "
      f"{md(ev.value('cardinality') or 'one record per occurrence')}")
    w("")
    if ev.body():
        w(md(ev.body()))
        w("")
    w("## Fields")
    w("")
    rows, notes = [], []
    for ln in ev.lines:
        if ln.kind == "include":
            g = cat.groups.get(ln.name)
            for p in (g.includes if g else []):
                f = cat.fields.get(p)
                rows.append([field_link(cat, p),
                             f"`{f.value('type')}`" if f else "?",
                             f"via {group_link(cat, ln.name)}",
                             cell(md(f.summary())) if f else ""])
            if not g:
                rows.append([f"`{ln.name}`", "group", "—",
                             "Not defined in the catalogue."])
            if ln.gloss():
                notes.append(f"- {group_link(cat, ln.name)}: "
                             f"{cell(md(ln.gloss()))}")
            continue
        f = cat.fields.get(ln.name)
        meaning = []
        if ln.gloss():
            meaning.append(md(ln.gloss()))
        elif f is not None:
            meaning.append(md(f.summary()))
        else:
            meaning.append("Not defined in the catalogue.")
        if ln.values:
            word = f" ({closed_word(ln.closed)} set)" if ln.closed else ""
            meaning.append(f"Values here{word}: {values_md(ln.values)}.")
        rows.append([field_link(cat, ln.name),
                     f"`{f.value('type')}`" if f else "?",
                     presence_md(ln.presence),
                     cell("\n\n".join(meaning))])
    if rows:
        o += table(["Field", "Type", "Presence", "Meaning"], rows)
        w("")
        o += notes
        if notes:
            w("")
    else:
        w("The payload carries no fields.")
        w("")
    w("Every record also carries the header fields of "
      f"[the envelope]({BOOK_REF}/introduction/the-envelope), which no "
      "payload repeats.")
    w("")
    w(generated_note(f"`{ev.fragment}`"))
    return "\n".join(o) + "\n"


def group_page(cat, g, carried_by):
    o = front(f"{g.name} group", g.summary())
    w = o.append
    o += broken_warning(cat, g.fragment)
    w(f"- **Group:** `{g.name}`")
    w(f"- **Defined in:** `{g.fragment}`")
    w("")
    if g.body():
        w(md(g.body()))
        w("")
    w("## Fields")
    w("")
    rows = []
    for p in g.includes:
        f = cat.fields.get(p)
        rows.append([field_link(cat, p),
                     f"`{f.value('type')}`" if f else "?",
                     cell(md(f.summary())) if f
                     else "Not defined in the catalogue."])
    o += table(["Field", "Type", "Meaning"], rows)
    w("")
    w("## Carried by")
    w("")
    if carried_by:
        for e in carried_by:
            w(f"- {event_link(e)}")
    else:
        w("No event includes this group yet.")
    w("")
    w(generated_note(f"`{g.fragment}`"))
    return "\n".join(o) + "\n"


def field_entry(cat, f, carried, groups):
    o = []
    w = o.append
    w(f'## <a id="{f.name}"></a>`{f.name}`')
    w("")
    w(f"- **Type:** `{f.value('type') or 'not declared'}`")
    if f.value("values"):
        w(f"- **Values:** {values_md(f.value('values'))}")
    if f.value("closed"):
        w(f"- **Set:** {closed_word(f.value('closed'))}")
    w(f"- **Asserted:** "
      f"{'yes' if f.value('asserted') == 'true' else 'no'}")
    w(f"- **Carried in:** "
      f"{'the header' if f.value('carried') == 'header' else 'the payload'}")
    w(f"- **Defined in:** `{f.fragment}`")
    if groups:
        w(f"- **In groups:** "
          + ", ".join(group_link(cat, g) for g in groups))
    w("")
    if f.body():
        w(md(f.body()))
        w("")
    w("**Carried by:**")
    w("")
    if f.value("carried") == "header":
        w("Every record, in the header.")
    elif carried:
        for e, via in carried:
            suffix = f" (via {group_link(cat, via)})" if via else ""
            w(f"- {event_link(e)}{suffix}")
    else:
        w("No event carries this field yet.")
    w("")
    return o


def field_root_page(cat, root, paths, by_path, groups_of):
    frags = sorted({cat.fields[p].fragment for p in paths})
    o = front(f"{root}.*",
              f"Every field the evman catalogue defines under {root}: its "
              "type, values and meaning, and the events that carry it.")
    w = o.append
    for fr in frags:
        o += broken_warning(cat, fr)
    w(f"Every field the catalogue defines under `{root}`, in path order. "
      "Each entry gives the field's definition and, under **Carried by**, "
      "every event type that writes it.")
    w("")
    for p in paths:
        o += field_entry(cat, cat.fields[p], by_path.get(p, []),
                         groups_of.get(p, []))
    w(generated_note(", ".join(f"`{fr}`" for fr in frags)))
    return "\n".join(o) + "\n"


def all_types_page(cat):
    o = front("All Event Types", ALL_TYPES_DESCRIPTION)
    w = o.append
    w(f"Every event type in the evman catalogue, generated from the "
      f"fragments by `{TOOL}`: {len(cat.events)} event types and "
      f"{len(cat.fields)} fields, from "
      + ", ".join(f"`{f}`" for f in cat.fragments) + ".")
    w("")
    w("The tier sets whether an event type is recorded by default "
      f"(PGSS {SECTION_SIGN}6.8). Each type links to its page; each page's "
      "fields link "
      "to the field index.")
    w("")
    for root, d, title in CHAPTERS:
        names = sorted(n for n in cat.events if chapter_of(n) == d)
        if not names:
            continue
        w(f"## {title}")
        w("")
        rows = [[event_link(n), md(cat.events[n].value("tier") or "—"),
                 f"`{cat.events[n].fragment}`",
                 cell(md(cat.events[n].summary()))] for n in names]
        o += table(["Event type", "Tier", "Fragment", "Summary"], rows)
        w("")
    w("## Not in the catalogue")
    w("")
    w("The registry's "
      f"[watch records]({BOOK_REF}/registry-watch-records/watch-records) "
      "are not events, so no fragment defines them and this table does not "
      "list them.")
    w("")
    w(generated_note("the evman catalogue"))
    return "\n".join(o) + "\n"


def chapter_toml(title):
    return f"title = {json.dumps(title, ensure_ascii=False)}\n"


def build(cat):
    """Return {path relative to the book: text} for every owned page."""
    out = {}
    unplaced = sorted(n for n in cat.events if chapter_of(n) is None)
    if unplaced:
        raise SystemExit(
            "event types with no chapter (add their root to CHAPTERS in "
            f"{TOOL}): " + ", ".join(unplaced))
    slugs = {}
    for n in cat.events:
        if slug(n) in slugs:
            raise SystemExit(f"{n} and {slugs[slug(n)]} share the page slug "
                             f"{slug(n)}")
        slugs[slug(n)] = n

    by_path = carriers(cat)
    by_group = group_carriers(cat)
    groups_of = member_of(cat)

    if cat.groups:
        out[f"{GROUPS_DIR}/trail.toml"] = chapter_toml("Groups")
        for i, g in enumerate(sorted(cat.groups), 1):
            out[f"{GROUPS_DIR}/{i}--group-{g}.md"] = group_page(
                cat, cat.groups[g], by_group.get(g, []))

    for root, d, title in CHAPTERS:
        names = sorted(n for n in cat.events if chapter_of(n) == d)
        if not names:
            continue
        out[f"{d}/trail.toml"] = chapter_toml(title)
        for i, n in enumerate(names, 1):
            out[f"{d}/{i}--{slug(n)}.md"] = event_page(cat, cat.events[n])

    out[ALL_TYPES] = all_types_page(cat)

    roots = {}
    for p in cat.fields:
        roots.setdefault(field_root(p), []).append(p)
    out[f"{FIELD_INDEX_DIR}/trail.toml"] = chapter_toml("Field Index")
    for i, r in enumerate(sorted(roots), 1):
        out[f"{FIELD_INDEX_DIR}/{i}--fields-{r}.md"] = field_root_page(
            cat, r, sorted(roots[r]), by_path, groups_of)
    return out


# --- writing -------------------------------------------------------------

def on_disk():
    """Every file currently in an owned place, relative to the book."""
    found = set()
    for d in OWNED_DIRS:
        base = BOOK / d
        if base.exists():
            found |= {str(p.relative_to(BOOK)) for p in base.rglob("*")
                      if p.is_file()}
    for f in OWNED_FILES:
        if (BOOK / f).exists():
            found.add(f)
    return found


def learn_is_absent():
    """True when there is no learn/ checkout beside pkm/ to write into.

    A pkm checkout on its own is a legitimate state, and so is a build
    container that mounts only pkm/ -- neither is drift.
    """
    return not BOOK.exists()


def main():
    if learn_is_absent():
        print(f"skipped: no learn/ checkout at {BOOK}", file=sys.stderr)
        return 0
    cat = load()
    for fragment, n, msg in cat.problems:
        print(f"warning: {fragment}:{n}: {msg}", file=sys.stderr)
    pages = build(cat)
    existing = on_disk()
    stale = sorted(existing - set(pages))

    if "--check" in sys.argv:
        drift = [p for p in sorted(pages)
                 if not (BOOK / p).exists() or (BOOK / p).read_text()
                 != pages[p]]
        for p in drift:
            print(f"out of date: {p}", file=sys.stderr)
        for p in stale:
            print(f"not generated: {p}", file=sys.stderr)
        if drift or stale:
            print(f"{BOOK} is out of date; regenerate with "
                  "gen-events-book.py", file=sys.stderr)
            return 1
        print("up to date")
        return 0

    for p in stale:
        (BOOK / p).unlink()
    for d in OWNED_DIRS:
        base = BOOK / d
        if base.exists():
            for sub in sorted(base.rglob("*"), reverse=True):
                if sub.is_dir() and not any(sub.iterdir()):
                    sub.rmdir()
            if not any(base.iterdir()):
                base.rmdir()
    written = 0
    for p, text in sorted(pages.items()):
        target = BOOK / p
        if target.exists() and target.read_text() == text:
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
        written += 1
    print(f"wrote {written} of {len(pages)} pages under {BOOK.relative_to(ROOT)}"
          + (f", removed {len(stale)}" if stale else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
