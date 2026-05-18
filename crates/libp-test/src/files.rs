// `libp-test files <subcommand>` — KACS native file open probes.

use clap::Subcommand;
use libp_files::consts::{ACCESS_GENERIC_READ, ACCESS_GENERIC_WRITE};
use libp_files::{Disposition, OpenOptions, OpenStatus};
use serde::Serialize;

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Open `path` with the named disposition. Reports the open status.
    Open {
        #[arg(long)]
        path: String,
        /// One of: supersede | open | create | open-if | overwrite |
        /// overwrite-if.
        #[arg(long, default_value = "open")]
        disposition: String,
    },

    /// Create a fresh file (`Create` → expect Created), then open it
    /// (`Open` → expect Opened). Reports both statuses.
    CreateRoundtrip {
        #[arg(long)]
        path: String,
    },

    /// Create a file with delete-on-close set, then drop the handle.
    /// The file should not exist afterwards — the test verifies that.
    DeleteOnClose {
        #[arg(long)]
        path: String,
    },

    /// Open a path that should not exist with `Open` disposition.
    /// Expected to fail with ENOENT — surfaces the errno.
    OpenMissing {
        #[arg(long)]
        path: String,
    },
}

pub fn run(cmd: Cmd) {
    let out = match cmd {
        Cmd::Open { path, disposition } => open(&path, &disposition),
        Cmd::CreateRoundtrip { path } => create_roundtrip(&path),
        Cmd::DeleteOnClose { path } => delete_on_close(&path),
        Cmd::OpenMissing { path } => open_missing(&path),
    };
    println!("{}", serde_json::to_string(&out).unwrap());
}

fn parse_disposition(s: &str) -> Result<Disposition, String> {
    match s {
        "supersede" => Ok(Disposition::Supersede),
        "open" => Ok(Disposition::Open),
        "create" => Ok(Disposition::Create),
        "open-if" => Ok(Disposition::OpenIf),
        "overwrite" => Ok(Disposition::Overwrite),
        "overwrite-if" => Ok(Disposition::OverwriteIf),
        other => Err(format!("unknown disposition {other:?}")),
    }
}

fn status_name(s: OpenStatus) -> &'static str {
    match s {
        OpenStatus::Opened => "Opened",
        OpenStatus::Created => "Created",
        OpenStatus::Overwritten => "Overwritten",
        OpenStatus::Superseded => "Superseded",
    }
}

fn err(e: libp_files::Error) -> serde_json::Value {
    let errno = match &e {
        libp_files::Error::Syscall(errno) => Some(serde_json::json!({
            "name": errno.name(),
            "raw": errno.raw(),
        })),
        _ => None,
    };
    serde_json::json!({ "ok": false, "error": e.to_string(), "errno": errno })
}

fn err_msg(msg: &str) -> serde_json::Value {
    serde_json::json!({ "ok": false, "error": msg })
}

#[derive(Serialize)]
struct OpenResult {
    ok: bool,
    disposition: String,
    status: &'static str,
}

fn open(path: &str, disposition: &str) -> serde_json::Value {
    let disp = match parse_disposition(disposition) {
        Ok(d) => d,
        Err(m) => return err_msg(&m),
    };
    // Request read+write so the truncating dispositions (overwrite,
    // overwrite-if, supersede) have the access they need — opening a
    // file for truncation with read-only access is rejected EINVAL.
    let opts = OpenOptions::new()
        .desired_access(ACCESS_GENERIC_READ | ACCESS_GENERIC_WRITE)
        .disposition(disp);
    match opts.open(path) {
        Ok((_handle, status)) => serde_json::to_value(OpenResult {
            ok: true,
            disposition: disposition.into(),
            status: status_name(status),
        })
        .unwrap(),
        Err(e) => err(e),
    }
}

#[derive(Serialize)]
struct RoundtripResult {
    ok: bool,
    create_status: &'static str,
    open_status: &'static str,
}

fn create_roundtrip(path: &str) -> serde_json::Value {
    // Create the file fresh.
    let create = OpenOptions::new()
        .desired_access(ACCESS_GENERIC_WRITE)
        .disposition(Disposition::Create);
    let create_status = match create.open(path) {
        Ok((_h, s)) => s,
        Err(e) => return err(e),
    };
    // Then open the now-existing file.
    let open = OpenOptions::new()
        .desired_access(ACCESS_GENERIC_READ)
        .disposition(Disposition::Open);
    let open_status = match open.open(path) {
        Ok((_h, s)) => s,
        Err(e) => return err(e),
    };
    serde_json::to_value(RoundtripResult {
        ok: true,
        create_status: status_name(create_status),
        open_status: status_name(open_status),
    })
    .unwrap()
}

fn delete_on_close(path: &str) -> serde_json::Value {
    let opts = OpenOptions::new()
        .desired_access(ACCESS_GENERIC_WRITE)
        .disposition(Disposition::Create)
        .delete_on_close();
    match opts.open(path) {
        Ok((handle, status)) => {
            // Drop the handle now — the file should vanish.
            drop(handle);
            serde_json::json!({
                "ok": true,
                "create_status": status_name(status),
                "handle_dropped": true,
            })
        }
        Err(e) => err(e),
    }
}

fn open_missing(path: &str) -> serde_json::Value {
    let opts = OpenOptions::new()
        .desired_access(ACCESS_GENERIC_READ)
        .disposition(Disposition::Open);
    match opts.open(path) {
        Ok((_h, status)) => serde_json::json!({
            "ok": true,
            "unexpectedly_opened": true,
            "status": status_name(status),
        }),
        Err(e) => err(e),
    }
}
