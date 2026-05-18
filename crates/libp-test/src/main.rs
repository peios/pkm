// libp-test — JSON-CLI bridge exposing the libp-* crates to Provium tests.
//
// Each subcommand performs a self-contained operation and prints a JSON
// object to stdout. The schema is:
//
//   {"ok": true,  ...result fields...}     // success
//   {"ok": false, "error": "...", ...}      // failure
//
// All subcommands return exit code 0 — the JSON payload carries success
// vs failure. Use exit codes only for ARGV-parsing failures (clap's
// default behavior).
//
// Subcommand families:
//   token   — KACS token operations (this file's only family today)
//   sd      — Security Descriptor operations (Phase 3)
//   files   — KACS file open + handle ops (Phase 4)
//   event   — KMES emit + ring-buffer consumer (Phase 5)

use clap::{Parser, Subcommand};

mod event;
mod files;
mod sd;
mod token;

#[derive(Parser, Debug)]
#[command(
    name = "libp-test",
    version,
    about = "JSON-CLI bridge for libp-* integration tests"
)]
struct Cli {
    #[command(subcommand)]
    family: Family,
}

#[derive(Subcommand, Debug)]
enum Family {
    /// KACS token operations.
    #[command(subcommand)]
    Token(token::Cmd),
    /// Security Descriptor construction + get_sd/set_sd.
    #[command(subcommand)]
    Sd(sd::Cmd),
    /// KACS native file open (kacs_open).
    #[command(subcommand)]
    Files(files::Cmd),
    /// KMES event emission + ring-buffer consumption.
    #[command(subcommand)]
    Event(event::Cmd),
}

fn main() {
    let cli = Cli::parse();
    match cli.family {
        Family::Token(cmd) => token::run(cmd),
        Family::Sd(cmd) => sd::run(cmd),
        Family::Files(cmd) => files::run(cmd),
        Family::Event(cmd) => event::run(cmd),
    }
}
