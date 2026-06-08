# Kernel regman fragments

`regman` documentation for the registry knobs the PKM kernel reads. These
fragments install to `/usr/share/regman/`, where `regman <path> [value]`
finds them. regman never reads the live registry or LCS — the registry
stores typed-but-opaque blobs, so the *meaning* of each knob lives here.
See `peios/regman-design.md` for the format and lookup model.

| File | Subtree | Source of truth |
|---|---|---|
| `kmes.regman` | `Machine\System\KMES` | PSD-003 §6; `pkm/uapi/pkm/kmes.h` constants |
| `lcs.regman` | `Machine\System\Registry` | PSD-005 §11.4 / §8.2; `pkm/crates/lcs-core/src/config.rs` (`LCS_CONFIG_RANGES`) |

Every documented default / min / max was cross-checked against both the
spec table and the compiled-in constant; they agree exactly. Keep them in
sync when a knob's range changes — the constant is authoritative for
behaviour, this file for the prose.

KACS has no registry-configuration surface and so has no fragment here.

## Authoring

Write only the `canonical:` field on each record; the fence-line anchor is
derived, not hand-written. After editing:

```
regman fmt  kmes.regman lcs.regman   # bake folded anchors from canonical
regman lint kmes.regman lcs.regman   # verify framing, anchors, structure
```

The body's first line is the one-sentence summary shown in the key-level
`Values` index, so lead each value doc with a complete summary sentence.
Inline markup is `**bold**` and `` `code` `` only (single-asterisk
emphasis renders literally — do not use it).
