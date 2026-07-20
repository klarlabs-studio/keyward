//! Chrome native-messaging host for the browser extension — the CLI (prototype)
//! host that unlocks from a master-password file.
//!
//! The wire protocol and request handling live in `keyward_passbook::bridge`, so
//! this host and the desktop app (issue #13) answer the extension identically.
//! This module is only the CLI's entry point into that shared `serve` loop: it
//! binds locked stdio and reports the CLI's own version.

use keyward_passbook::Entry;
use std::io;

/// Serve native-messaging requests over stdio until the browser closes the pipe.
pub fn run(entries: &[Entry]) -> io::Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    keyward_passbook::bridge::serve(
        stdin.lock(),
        stdout.lock(),
        entries,
        env!("CARGO_PKG_VERSION"),
        crate::now_unix,
    )
}
