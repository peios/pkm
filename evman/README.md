# Kernel evman fragments

`evman` documentation for the events the PKM kernel writes and the fields
they carry. These fragments install to `/usr/share/evman/`, where
`evman <event-type | field>` finds them — `kernel.package.pekit.toml` maps
each one from `@source:`. evman never reads the event stream: a record
carries a type name and a MessagePack payload, so the *meaning* of each
event and field lives here. The format and its rules are PGSS §6.10
(learn, Events → The Catalogue); field naming is §6.4.

**The fragments are the catalogue.** A field that no fragment defines is
not approved, and nothing may emit it (PGSS §6.4). Adding a `--- field`
record is adding a field to the platform's vocabulary: it goes to Jack
first (PEI-617).

## Coverage

The emit sites are the list to check this against: every event type the
kernel writes is described here, and every field one of them carries is
defined in exactly one fragment.

| File | Defines | Events | Source of truth |
|---|---|---|---|
| `kernel.evman` | The platform fragment: the header fields, and every generic root (`subject`, `object`, `source`, `destination`, `emitter`, `event`, `access`, `outcome`, `trigger`, `operation`, `config`, `policy`, `transaction`, `fields`) | none | PGSS §6.4; `pkm/uapi/pkm/kmes.h` for the header |
| `kacs.evman` | `privilege.*`, `caap.*`, `linux.cap`, `mitigation.*`, `signature.*`, and other things only KACS knows | `kacs.audit.access.checked`, `kacs.audit.handle.used`, `kacs.audit.privilege.used`, `kacs.caap.sacl.skipped`, `kacs.caap.staging.diverged`, `kacs.session.destroyed` | `pkm/kacs/kmes_payload.rs`, `pkm/kacs/file_access.c`, `pkm/crates/kacs-core/src/access_check.rs` |
| `kmes.evman` | `buffer.*`, `loss.*` | `kmes.config.value.rejected`, `kmes.buffer.swap.failed` | `pkm/kmes/kmes.c` |
| `lcs.evman` | `source.rsi.*`, `request.*` | `lcs.audit.key.opened`, `lcs.audit.backup.{started,ended}`, `lcs.audit.restore.{started,ended}`, `lcs.source.response.rejected`, `lcs.config.value.rejected` | `pkm/crates/lcs-core/src/audit.rs` |
| `ntfe.evman` | `network.*`, `rule.*`, `flow.*`, NTFE's endpoint attribution | `ntfe.verdict.reported` | `pkm/ntfe/report.c` |
| `stratafs.evman` | `source.stratum.*`, `destination.stratum.*` | `stratafs.file.copied-up`, `stratafs.mutation.refused` | `pkm/kacs/file_access.c` (StrataFS records are written through KACS) |

Userspace components ship their own fragments from their own repos
(`peinit/peinit.evman`, `peipkg/peipkg.evman`, `eventd/eventd.evman`), as
their `.regman` files are.

## Ownership

Who may define a path is PGSS §6.10 rule 5, and the lint enforces it. In
short:

- The generic roots, and the common things beneath the roles (`token`,
  `process`, `file`, `key`, `session`), are defined in `kernel.evman` and
  nowhere else, even when only one subsystem carries them today.
- A subsystem defines the subtrees of things only it knows about —
  StrataFS's `source.stratum.*` — and any domain of its own, such as
  KMES's `buffer`.
- Anything may *carry* a field another fragment defines. Carrying is a
  `field:` line on an event; defining is a `--- field` record.

## Authoring

The anchor is the name itself — there is no folded anchor to bake, so
there is no `fmt` step. After editing:

```
evman lint *.evman     # verify framing, names and the §6.10 rules
```

Lint all the fragments together, userspace ones included: the rules that
matter most — one definition per path, no path both a value and a map —
are only checkable across the whole catalogue. `evman` is built from
peiosutils (`cargo build -p pu_evman`).

The prose's first sentence is the summary `evman` shows in an index, so
lead every record with a complete summary sentence. Inline markup is
`**bold**` and `` `code` `` only.

What lint will not tell you:

- **That a value list is right.** Take enumeration values from the code
  — a `uapi/pkm/trace.h` family, an encoder's name table — never from
  memory, and re-check them when the code changes.
- **That a field is emitted.** A record describes what the field means;
  whether an event carries it is the event's `field:` line, and whether
  the code writes it is the code. Records for fields no event carries yet
  say so.
- **That a condition is true.** `when outcome.success == false` is checked
  for naming a field the event carries, not for matching what the emitter
  does.
