# Kernel regman fragments

`regman` documentation for the registry the PKM kernel reads. These
fragments install to `/usr/share/regman/`, where `regman <path> [value]`
finds them — `kernel.package.pekit.toml` maps each one from `@source:`.
regman never reads the live registry or LCS: the registry stores
typed-but-opaque blobs, so the *meaning* of each key lives here. The
format and the authoring rules are in learn, "Writing regman pages".

## Coverage

`lcs/source_bootstrap.c` is the list to check this against: it discovers
every registry root the kernel reads, and there are five. All five are
documented here.

| File | Subtree | Source of truth |
|---|---|---|
| `lcs.regman` | `Machine\System\Registry` (LCS tunables) | Kernel TRM → LCS; `pkm/crates/lcs-core/src/config.rs` (`LCS_CONFIG_RANGES`) |
| `lcs.regman` | `Machine\System\Registry\Layers` (layer metadata) | Kernel TRM → LCS → Layers; `pkm/lcs/layer_metadata.c`, `pkm/lcs/key_fd.c` |
| `kmes.regman` | `Machine\System\KMES` | Kernel TRM → KMES; `pkm/uapi/pkm/kmes.h` constants |
| `net.regman` | `Machine\System\Network\TcpIp\PortReservations` | Kernel TRM → KACS → Network objects; `pkm/uapi/pkm/net.h`; `pkm/crates/kacs-core/src/port_reservation.rs` |
| `pnp.regman` | `Machine\System\Network\Rules` | Network policy reference; `pkm/pnp/ingest.c`; `pkm/crates/pnp-core/src/ingest.rs` |

Every documented default / min / max was cross-checked against both the
spec and the compiled-in constant; they agree exactly. Keep them in sync
when a range changes — the constant is authoritative for behaviour, this
file for the prose.

Two boundaries worth remembering:

- Port reservations are KACS's one registry surface; the rest of KACS has
  none.
- The kernel also *reads* `Machine\System\Network\Interfaces\` and
  `Networks\` for the PNP network context, but netd writes them and netd
  documents them. Owner documents; reader does not.

## Families

Several of these subtrees are keyed by instance — a layer name, a port
selector, a rule name. Those are documented once with a `<…>` component
in the `canonical`, which regman matches against a concrete path:
`regman Machine\System\Registry\Layers\base Precedence` answers from the
`Layers\<LayerName> Precedence` record.

`<name>` is one path component. `<name...>` spans separators, matching one
component or many, which is what the PNP rule forest needs: an exception
is a subkey of a rule, nesting to twelve, and `Rules\<Layer>\<rule...>`
answers at every depth. Use the spanning form only where the subtree is
genuinely a tree whose vocabulary does not change with depth — a narrower
page always wins over a broader one, so a `<name>` record beside a
`<name...>` record is not a conflict.

A wildcard also works in the *value* half of an anchor, which is how PNP
documents rule conditions: one record per fact, with the operator
wildcarded (`DstPort.<op>` covers `Equal`, `GreaterThan`, `LessThan` and
`Present`). Two traps there:

- **A wildcard stops at `\` and at a space, but not at a dot.** So
  `Local.<op>` would happily match `Local.User.Equal` and collide with
  that fact's own page. Any fact whose name is a prefix of another's —
  `Local`, `Remote`, `Interface` — gets one record per operator instead.
- **A wildcard never crosses a space**, so a value name containing one
  cannot be reached. The counter view `Counter.dns(1h, SrcAddr)` is the
  live case; `Counter.dns(1h,SrcAddr)` is the same view to the parser and
  does resolve. That caveat is on the `Counter` card itself.

## Authoring

Write only the `canonical:` field on each record; the fence-line anchor is
derived, not hand-written. After editing:

```
regman fmt  *.regman   # bake folded anchors from canonical
regman lint *.regman   # verify framing, anchors, structure
```

The body's first line is the one-sentence summary shown in the key-level
`Values` index, so lead each value doc with a complete summary sentence.
Inline markup is `**bold**` and `` `code` `` only (single-asterisk
emphasis renders literally — do not use it).

`lint` checks structure and anchors, not completeness: it will not tell
you that a value doc is missing `valid:`. Every value doc here carries all
four of `type`, `default`, `valid` and `applies`; keep it that way.
