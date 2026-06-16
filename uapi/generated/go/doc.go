// Package uapi is the generated Go mirror of the PKM kernel ABI.
//
// Every declaration here is generated from the C headers in pkm/uapi/pkm/
// by gen.sh — those headers are the single source of truth. Do not edit
// ztypes.go or zconst.go by hand; run ./gen.sh to regenerate them.
//
// This is the raw, mechanical binding layer: C names are kept verbatim,
// only capitalised for export (KACS_TOKEN_QUERY, struct kacs_query_args ->
// Kacs_query_args), and struct padding members appear as the blank
// identifier _. Ergonomic, idiomatic Go wrappers belong in libp-go, which
// consumes this package.
package uapi
