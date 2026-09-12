// Copyright 2026 Proof Engine Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0
//! Minimal blocking HTTP/1.1 plumbing for the reference API.
//!
//! Deliberately small: `Connection: close`, `Content-Length` bodies only
//! (bounded before buffering), no chunked reads, no keep-alive, no TLS.
//! Anything fancier (timeouts aside) belongs in a production deployment,
//! not in the reference.

use std::io::{Read, Write};
use std::net::TcpStream;

use crate::api;

const MAX_BODY_BYTES: usize = 8 << 20;

/// Handle one accepted connection: parse head, bound the body, route,
/// respond. Never panics on hostile input — every failure is a status
/// code (`400`/`404`/`405`/`413`/`422`), never a crash.
pub fn handle(mut stream: TcpStream) {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut head = vec![0u8; 8192];
    let mut raw = Vec::new();
    let header_end = loop {
        match stream.read(&mut head) {
            Ok(0) => return,
            Ok(n) => {
                raw.extend_from_slice(&head[..n]);
                if raw.len() > 16384 {
                    respond(&mut stream, 413, &api::err_json("headers too large"));
                    return;
                }
                if let Some(p) = find_header_end(&raw) {
                    break p;
                }
            }
            Err(_) => return,
        }
    };
    let head_text = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let mut lines = head_text.lines();
    let request_line = lines.next().unwrap_or("").to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let mut content_length: Option<usize> = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(v) = line
            .strip_prefix("Content-Length:")
            .or_else(|| line.strip_prefix("content-length:"))
        {
            content_length = v.trim().parse().ok();
        }
    }
    let mut body = raw[header_end..].to_vec();
    if method == "POST" {
        let len = match content_length {
            Some(n) if n <= MAX_BODY_BYTES => n,
            _ => {
                respond(
                    &mut stream,
                    413,
                    &api::err_json("body required with Content-Length ≤ 8 MiB"),
                );
                return;
            }
        };
        while body.len() < len {
            let mut chunk = vec![0u8; 8192];
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(_) => return,
            }
            if body.len() > MAX_BODY_BYTES + 16384 {
                respond(&mut stream, 413, &api::err_json("body too large"));
                return;
            }
        }
        body.truncate(len);
    }
    let (status, out) = api::route(&method, &path, &body);
    respond(&mut stream, status, &out);
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn respond(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        422 => "Unprocessable Entity",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.write_all(body.as_bytes());
}
