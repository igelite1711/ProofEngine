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
use std::sync::atomic::{AtomicU64, Ordering};

use crate::api;

const MAX_BODY_BYTES: usize = 8 << 20;

/// Process counters since start. Safe to log/export: paths are fixed
/// routes, statuses are codes, byte counts are sizes — never payloads,
/// headers, keys, or evidence.
#[derive(Debug, Default)]
pub struct Metrics {
    pub requests: AtomicU64,
    pub ok_2xx: AtomicU64,
    pub err_4xx: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
}

impl Metrics {
    /// Snapshot as JSON (powers `GET /v1/metrics`).
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "requests_total": self.requests.load(Ordering::Relaxed),
            "responses_2xx": self.ok_2xx.load(Ordering::Relaxed),
            "responses_4xx": self.err_4xx.load(Ordering::Relaxed),
            "bytes_in": self.bytes_in.load(Ordering::Relaxed),
            "bytes_out": self.bytes_out.load(Ordering::Relaxed),
        })
    }

    fn record(&self, status: u16, bytes_in: u64, bytes_out: u64) {
        self.requests.fetch_add(1, Ordering::Relaxed);
        if (200..300).contains(&status) {
            self.ok_2xx.fetch_add(1, Ordering::Relaxed);
        } else {
            self.err_4xx.fetch_add(1, Ordering::Relaxed);
        }
        self.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
    }
}

/// Handle one accepted connection: parse head, bound the body, route,
/// respond. Returns the status served (for access logging by the caller).
/// Never panics on hostile input — every failure is a status code
/// (`400`/`404`/`405`/`413`/`422`), never a crash.
pub fn handle(stream: TcpStream, metrics: &Metrics) -> u16 {
    handle_inner(stream, metrics)
}

fn respond_with(metrics: &Metrics, stream: &mut TcpStream, status: u16, body: &str) -> u16 {
    metrics.record(status, 0, body.len() as u64);
    respond(stream, status, body);
    status
}

fn handle_inner(mut stream: TcpStream, metrics: &Metrics) -> u16 {
    let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let mut head = vec![0u8; 8192];
    let mut raw = Vec::new();
    let header_end = loop {
        match stream.read(&mut head) {
            Ok(0) => return 0,
            Ok(n) => {
                raw.extend_from_slice(&head[..n]);
                if raw.len() > 16384 {
                    return respond_with(
                        metrics,
                        &mut stream,
                        413,
                        &api::err_json("headers too large"),
                    );
                }
                if let Some(p) = find_header_end(&raw) {
                    break p;
                }
            }
            Err(_) => return 0,
        }
    };
    let head_text = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let mut lines = head_text.lines();
    let request_line = lines.next().unwrap_or("").to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("").to_string();
    // Strict request line: METHOD PATH HTTP/1.x. Anything else (HTTP/2
    // preface, garbage, missing version) is a 400, never guessed.
    if method.is_empty() || path.is_empty() || !(version == "HTTP/1.0" || version == "HTTP/1.1") {
        return respond_with(
            metrics,
            &mut stream,
            400,
            &api::err_json("bad request line"),
        );
    }
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
                return respond_with(
                    metrics,
                    &mut stream,
                    413,
                    &api::err_json("body required with Content-Length ≤ 8 MiB"),
                );
            }
        };
        while body.len() < len {
            let mut chunk = vec![0u8; 8192];
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => body.extend_from_slice(&chunk[..n]),
                Err(_) => return 0,
            }
            if body.len() > MAX_BODY_BYTES + 16384 {
                return respond_with(metrics, &mut stream, 413, &api::err_json("body too large"));
            }
        }
        body.truncate(len);
    }
    // GET /v1/metrics is served here (needs live counters); everything else
    // routes to the pure verifier.
    if method == "GET" && path == "/v1/metrics" {
        return respond_with(metrics, &mut stream, 200, &metrics.snapshot().to_string());
    }
    let in_bytes = body.len() as u64;
    let (status, out) = api::route(&method, &path, &body);
    metrics.record(status, in_bytes, out.len() as u64);
    respond(&mut stream, status, &out);
    status
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
