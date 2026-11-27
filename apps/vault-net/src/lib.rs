//! amethystora-vault-net, the Vault's only way out (plans/done/PLAN-vault.md, "Sync with Vaultwarden and Bitwarden"). The vault's
//! service, which has no network, hands it one request at a time over a socket only that service can open, and it hands
//! back what the server said. It holds no key and keeps nothing: Bitwarden's protocol encrypts on the client, so what passes
//! through here is ciphertext, a token and at a password login the master password's hash, each for the one request.
//!
//! One line of JSON each way, as the Vault's own socket:
//!
//! ```text
//! {"v":1,"op":"session","origins":["https://vault.example.test:443"],"ca":PEM?,"pin":HEX?}   -> {"ok":true}
//! {"v":1,"op":"request","method":"GET","url":"...","headers":[["Name","value"]],"body":B64} -> {"ok":true,"status":200,"body":B64,"headers":[["dpop-nonce","..."]]}
//!                                                                                            (`headers`: `http::ANSWER_HEADERS` only, names in lower case, values as written, [] if none)
//! {"v":1,"op":"probe","origin":"https://vault.example.test:443"}                             -> {"ok":true,"trusted":bool,"chain":[...]}
//! anything refused                                                                          -> {"ok":false,"why":"not-allowed"}
//! ```
//!
//! A request needs a session first, on the same connection, and reaches only its origins.

pub mod alloc;
pub mod http;

use std::io::{BufRead, Read, Write};

use base64::Engine;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use http::{Failure, Session};

pub const SOCKET: &str = "/run/amethystora/vault-net.sock";
/// A request's line: a 16 MiB file of Kemlock's, in base64 and in a little JSON (an item of Bitwarden's is far under this)
pub const MOST_REQUEST: usize = 24 * 1024 * 1024;
/// An answer's line: the largest body, in base64, and a little JSON
pub const MOST_ANSWER: usize = http::MOST_BODY / 3 * 4 + 4096;

/// Makes a session from the origins, the CA and the pin a `session` line named
pub type MakeSession = dyn Fn(Vec<String>, Option<&str>, Option<&str>) -> Result<Session, Failure>;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn refusal(why: Failure) -> Value {
    json!({"ok": false, "why": why.name()})
}

/// One connection's lines, each answered before the next is read, until the other end closes
pub fn serve(reader: &mut dyn BufRead, writer: &mut dyn Write, make_session: &MakeSession) {
    let mut session: Option<Session> = None;
    loop {
        let mut line = Zeroizing::new(Vec::new());
        match (&mut *reader).take(MOST_REQUEST as u64 + 1).read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if line.len() > MOST_REQUEST || line.last() != Some(&b'\n') {
            let _ = writeln!(writer, "{}", refusal(Failure::TooLarge));
            return;
        }
        let answer = answer(&line, &mut session, make_session);
        let text = Zeroizing::new(answer.to_string());
        if writer.write_all(text.as_bytes()).and_then(|()| writer.write_all(b"\n")).and_then(|()| writer.flush()).is_err() {
            return;
        }
    }
}

fn answer(line: &[u8], session: &mut Option<Session>, make_session: &MakeSession) -> Value {
    let Ok(body) = serde_json::from_slice::<Value>(line) else { return refusal(Failure::NotAllowed) };
    if body.get("v").and_then(Value::as_u64) != Some(1) {
        return refusal(Failure::NotAllowed);
    }
    match body.get("op").and_then(Value::as_str) {
        Some("session") => {
            let origins: Vec<String> = body.get("origins").and_then(Value::as_array).into_iter().flatten().filter_map(|o| o.as_str().map(str::to_string)).collect();
            let text = |name: &str| body.get(name).and_then(Value::as_str);
            match make_session(origins, text("ca"), text("pin")) {
                Ok(made) => {
                    *session = Some(made);
                    json!({"ok": true})
                }
                Err(why) => refusal(why),
            }
        }
        Some("request") => {
            let Some(session) = session.as_mut() else { return refusal(Failure::NotAllowed) };
            let (Some(method), Some(url)) = (body.get("method").and_then(Value::as_str), body.get("url").and_then(Value::as_str)) else { return refusal(Failure::NotAllowed) };
            let headers: Vec<(String, String)> = body
                .get("headers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|pair| Some((pair.get(0)?.as_str()?.to_string(), pair.get(1)?.as_str()?.to_string())))
                .take(32)
                .collect();
            let Ok(sent) = B64.decode(body.get("body").and_then(Value::as_str).unwrap_or("")).map(Zeroizing::new) else { return refusal(Failure::NotAllowed) };
            match session.request_full(method, url, &headers, &sent) {
                Ok(reply) => json!({"ok": true, "status": reply.status, "body": B64.encode(&reply.body[..]), "headers": reply.headers}),
                Err(why) => refusal(why),
            }
        }
        Some("probe") => match body.get("origin").and_then(Value::as_str).map(http::probe) {
            Some(Ok(seen)) => {
                let chain: Vec<Value> = seen.chain.into_iter().map(|(subject, issuer, sha256, pem, self_signed)| json!({"subject": subject, "issuer": issuer, "sha256": sha256, "pem": pem, "self_signed": self_signed})).collect();
                json!({"ok": true, "trusted": seen.trusted, "chain": chain})
            }
            Some(Err(why)) => refusal(why),
            None => refusal(Failure::NotAllowed),
        },
        _ => refusal(Failure::NotAllowed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Read, Write};
    use std::net::TcpListener;

    /// A server that reads one whole request (head and body), answers it with a nonce and a cookie, and gives back what it read
    fn server() -> (String, std::thread::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let thread = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut got = Vec::new();
            let mut chunk = vec![0u8; 64 * 1024];
            let (head, length) = loop {
                let count = socket.read(&mut chunk).unwrap();
                got.extend_from_slice(&chunk[..count]);
                if let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&got[..at]).to_string();
                    let length = head.lines().find_map(|l| l.strip_prefix("Content-Length: ")).unwrap().parse::<usize>().unwrap();
                    break (at + 4, length);
                }
            };
            while got.len() < head + length {
                let count = socket.read(&mut chunk).unwrap();
                got.extend_from_slice(&chunk[..count]);
            }
            socket.write_all(b"HTTP/1.1 201 Created\r\nDPoP-Nonce: Nonce-AbC\r\nSet-Cookie: a=b\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}").unwrap();
            length
        });
        (origin, thread)
    }

    fn talk(script: &[u8]) -> Vec<Value> {
        let mut reader = BufReader::new(script);
        let mut written = Vec::new();
        serve(&mut reader, &mut written, &|origins, ca, pin| Session::new(origins, ca, pin));
        String::from_utf8(written).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect()
    }

    fn lines(origin: &str, body: &[u8]) -> Vec<u8> {
        let session = json!({"v": 1, "op": "session", "origins": [origin]});
        let request = json!({"v": 1, "op": "request", "method": "POST", "url": format!("{origin}/kem/v1/items:batch"), "headers": [["Content-Type", "application/octet-stream"]], "body": B64.encode(body)});
        format!("{session}\n{request}\n").into_bytes()
    }

    #[test]
    fn the_answer_to_a_request_carries_the_allowed_headers() {
        let (origin, thread) = server();
        let answers = talk(&lines(&origin, b"abc"));
        assert_eq!(thread.join().unwrap(), 3);
        assert_eq!(answers[0], json!({"ok": true}));
        assert_eq!(answers[1], json!({"ok": true, "status": 201, "body": B64.encode(b"{}"), "headers": [["dpop-nonce", "Nonce-AbC"], ["content-type", "application/json"]]}));
    }

    #[test]
    fn the_answer_has_a_headers_array_even_when_there_is_none() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut got = [0u8; 4096];
            let _ = socket.read(&mut got).unwrap();
            socket.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").unwrap();
        });
        let answers = talk(&lines(&origin, b""));
        assert_eq!(answers[1], json!({"ok": true, "status": 204, "body": "", "headers": []}));
    }

    #[test]
    fn a_line_between_four_and_twenty_four_mebibytes_is_taken_and_one_past_is_not() {
        // The 14 MiB body is some 18.7 MiB in base64: past the 4 MiB that was the limit, under the 24 that is
        let (origin, thread) = server();
        let script = lines(&origin, &vec![7u8; 14 * 1024 * 1024]);
        assert!(script.len() > 4 * 1024 * 1024 && script.len() < MOST_REQUEST);
        let answers = talk(&script);
        assert_eq!(thread.join().unwrap(), 14 * 1024 * 1024);
        assert_eq!(answers[1]["status"], 201);
        // One line past the limit is refused whole, and the connection ends
        let mut past = vec![b'x'; MOST_REQUEST + 1];
        past.push(b'\n');
        let answers = talk(&past);
        assert_eq!(answers, [json!({"ok": false, "why": "too-large"})]);
    }
}
