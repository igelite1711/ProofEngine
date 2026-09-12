// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! `proof-api` binary: loopback-only listener around [`proof_api::server`].

use std::net::TcpListener;

fn main() {
    let bind = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8902".into());
    if !bind.starts_with("127.") && !bind.starts_with("localhost") && !bind.starts_with("[::1]") {
        eprintln!("refusing non-loopback bind {bind} (see library docs)");
        std::process::exit(2);
    }
    let listener = TcpListener::bind(&bind).unwrap_or_else(|e| {
        eprintln!("bind {bind}: {e}");
        std::process::exit(2);
    });
    eprintln!("proof-api listening on {bind} (loopback only)");
    for stream in listener.incoming() {
        match stream {
            Ok(s) => proof_api::server::handle(s),
            Err(e) => eprintln!("accept: {e}"),
        }
    }
}
