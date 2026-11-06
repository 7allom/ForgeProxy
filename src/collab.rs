//! Out-of-band Application Security Testing (OAST) payload generator and polling client.
//! Generates unique tracking tokens using prefix hashing and keystream masking
//! to correlate external callbacks to active testing sessions.

const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
pub const PREFIX_LEN: usize = 8; // estimated
pub const CUSTOM_DATA_MAX: usize = 16; // CollaboratorClient.generatePayload javadoc

/// Custom data must be alphanumeric and at most 16 characters (API documentation).
pub fn valid_custom_data(s: &str) -> bool {
    s.len() <= CUSTOM_DATA_MAX && s.chars().all(|c| c.is_ascii_alphanumeric())
}

fn idx(c: u8) -> Option<u8> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u8)
}

fn check_char(a: u8, b: u8) -> u8 {
    ALPHABET[(idx(a).unwrap_or(0) as usize * 7 + idx(b).unwrap_or(0) as usize) % 36]
}

fn keystream(prefix: &[u8], i: usize) -> u8 {
    let p = prefix[i % prefix.len()];
    (idx(p).unwrap_or(0) as usize * 11 + i * 5) as u8 % 36
}

/// Build one payload. `seed` supplies randomness for the prefix; `counter` increments per payload.
pub fn generate(seed: u64, counter: u64, custom: &str, server: Option<&str>) -> String {
    let mut x = seed | 1;
    let prefix: Vec<u8> = (0..PREFIX_LEN)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            ALPHABET[(x % 36) as usize]
        })
        .collect();
    let plain = format!("{counter}y{}", custom.to_ascii_lowercase());
    let sealed: String = plain
        .bytes()
        .enumerate()
        .map(|(i, c)| ALPHABET[((idx(c).unwrap_or(0) + keystream(&prefix, i)) % 36) as usize] as char)
        .collect();
    let id = format!(
        "{}{}{}",
        String::from_utf8_lossy(&prefix),
        check_char(prefix[0], prefix[1]) as char,
        sealed
    );
    match server.map(str::trim).filter(|s| !s.is_empty()) {
        None => id,
        Some(s) if s.parse::<std::net::IpAddr>().is_ok() => format!("{s}.{id}"),
        Some(s) => format!("{id}.{}", s.trim_matches('.')),
    }
}

/// Read (counter, custom data) back from a payload's id, if it was made here.
pub fn decode(payload: &str) -> Option<(u64, String)> {
    let id = payload.split('.').find(|part| part.len() > PREFIX_LEN + 1 && part.bytes().all(|b| idx(b).is_some()))?;
    let b = id.as_bytes();
    let prefix = &b[..PREFIX_LEN];
    if b[PREFIX_LEN] != check_char(prefix[0], prefix[1]) {
        return None;
    }
    let plain: String = b[PREFIX_LEN + 1..]
        .iter()
        .enumerate()
        .map(|(i, &c)| idx(c).map(|v| ALPHABET[(v as usize + 36 - keystream(prefix, i) as usize) % 36] as char))
        .collect::<Option<String>>()?;
    let (n, custom) = plain.split_once('y')?;
    Some((n.parse().ok()?, custom.to_string()))
}

/// Extract the bare payload identifier from a Collaborator payload (stripping server domain/IP).
pub fn payload_id(payload: &str) -> &str {
    let trimmed = payload.trim();
    trimmed
        .split('.')
        .find(|part| part.len() > PREFIX_LEN + 1 && part.bytes().all(|b| idx(b).is_some()))
        .unwrap_or_else(|| trimmed.split('.').next().unwrap_or(trimmed))
}

/// One out-of-band interaction returned by a Collaborator or Interactsh polling endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CollabInteraction {
    /// Interaction protocol/type ("DNS", "HTTP", "HTTPS", "SMTP").
    #[serde(default, alias = "type", alias = "protocol", alias = "interactionType")]
    pub interaction_type: String,
    /// Client IP address that initiated the interaction.
    #[serde(
        default,
        alias = "client",
        alias = "remote-address",
        alias = "remote_address",
        alias = "source_ip",
        alias = "clientIp",
        alias = "ip"
    )]
    pub client_ip: String,
    /// Interaction timestamp (ISO-8601 / RFC-3339 or server time string).
    #[serde(default, alias = "time", alias = "time_stamp", alias = "timeStamp")]
    pub timestamp: String,
    /// Protocol-specific details (DNS query type/sub-domain, HTTP request line, SMTP conversation).
    #[serde(
        default,
        alias = "details",
        alias = "q-type",
        alias = "q_type",
        alias = "raw-request",
        alias = "raw_request",
        alias = "protocolDetails",
        alias = "query"
    )]
    pub protocol_details: String,
    /// Comment or decoded custom data annotation.
    #[serde(default, alias = "custom_data", alias = "customData", alias = "note")]
    pub comment: String,
    /// The Collaborator payload or correlation ID that was triggered.
    #[serde(
        default,
        alias = "id",
        alias = "interaction_id",
        alias = "interactionId",
        alias = "full-id",
        alias = "full_id",
        alias = "unique-id",
        alias = "unique_id"
    )]
    pub payload: String,
}

/// Envelope returned by Collaborator / Interactsh JSON polling endpoints.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CollabPollResponse {
    #[serde(default, alias = "responses", alias = "data", alias = "events")]
    pub interactions: Vec<CollabInteraction>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum PollWireFormat {
    Envelope(CollabPollResponse),
    List(Vec<CollabInteraction>),
    Single(CollabInteraction),
}

/// Build the generic OAST polling URL `http://{server}/poll?id={id}` (or `https://` / custom path when specified).
pub fn poll_url(server: &str, id: &str) -> String {
    let srv = server.trim().trim_end_matches('/');
    let base = if srv.starts_with("http://") || srv.starts_with("https://") {
        srv.to_string()
    } else {
        format!("http://{srv}")
    };
    let after_scheme = base.split_once("://").map(|(_, rest)| rest).unwrap_or(&base);
    if after_scheme.contains('/') {
        let sep = if base.contains('?') { '&' } else { '?' };
        format!("{base}{sep}id={id}")
    } else {
        format!("{base}/poll?id={id}")
    }
}

/// Parse a JSON poll response body into normalized [`CollabInteraction`] records.
pub fn parse_poll_response(body: &str, default_payload: &str) -> Result<Vec<CollabInteraction>, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let wire: PollWireFormat =
        serde_json::from_str(trimmed).map_err(|e| format!("Invalid Collaborator poll JSON: {e}"))?;
    let raw_list = match wire {
        PollWireFormat::Envelope(env) => env.interactions,
        PollWireFormat::List(list) => list,
        PollWireFormat::Single(item) => {
            if item.interaction_type.is_empty() && item.client_ip.is_empty() && item.timestamp.is_empty() {
                Vec::new()
            } else {
                vec![item]
            }
        }
    };
    Ok(raw_list
        .into_iter()
        .map(|mut hit| {
            if hit.interaction_type.trim().is_empty() {
                hit.interaction_type = "DNS".into();
            } else {
                hit.interaction_type = hit.interaction_type.trim().to_ascii_uppercase();
            }
            if hit.payload.trim().is_empty() {
                hit.payload = default_payload.to_string();
            }
            if hit.comment.trim().is_empty() {
                let custom = decode(&hit.payload)
                    .or_else(|| decode(default_payload))
                    .map(|(_, c)| c)
                    .filter(|c| !c.is_empty());
                hit.comment = match (hit.protocol_details.trim().is_empty(), custom) {
                    (false, Some(c)) => format!("{} (Custom data: {c})", hit.protocol_details.trim()),
                    (false, None) => hit.protocol_details.trim().to_string(),
                    (true, Some(c)) => format!("Custom data: {c}"),
                    (true, None) => String::new(),
                };
            }
            hit
        })
        .collect())
}

/// Poll the Collaborator server for a single payload using `ureq`.
pub fn poll_payload(
    agent: &ureq::Agent,
    server: &str,
    payload: &str,
) -> Result<Vec<CollabInteraction>, String> {
    let id = payload_id(payload);
    let url = poll_url(server, id);
    let resp = agent.get(&url).set("Accept", "application/json").call();
    match resp {
        Ok(r) => {
            let mut raw = Vec::new();
            let _ = std::io::Read::read_to_end(
                &mut std::io::Read::take(r.into_reader(), crate::http::MAX_BODY),
                &mut raw,
            );
            let text = String::from_utf8_lossy(&raw);
            parse_poll_response(&text, payload)
        }
        Err(ureq::Error::Status(code, r)) => Err(format!(
            "Collaborator server {server} returned HTTP {code} {}",
            r.status_text()
        )),
        Err(ureq::Error::Transport(e)) => {
            Err(format!("Collaborator server {server} is unreachable: {e}"))
        }
    }
}

/// Poll the Collaborator server for all generated payloads (or a server probe if no payloads exist yet).
pub fn poll_all(
    server: &str,
    payloads: &[String],
    opts: &crate::http::SendOptions,
) -> Result<Vec<CollabInteraction>, String> {
    let srv = server.trim();
    if srv.is_empty() {
        return Err("No Collaborator server set.".into());
    }
    let agent = crate::http::agent(true, opts)?;
    if payloads.is_empty() {
        return poll_payload(&agent, srv, "");
    }
    let mut out = Vec::new();
    for payload in payloads {
        let mut hits = poll_payload(&agent, srv, payload)?;
        out.append(&mut hits);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn payload_round_trip() {
        let p = generate(12345, 7, "Order42", Some("collab.example.net"));
        assert!(p.ends_with(".collab.example.net"));
        assert_eq!(decode(&p), Some((7, "order42".to_string())));
    }
    #[test]
    fn without_server_location_is_id_only() {
        let p = generate(99, 0, "", None);
        assert!(!p.contains('.'));
        assert_eq!(decode(&p), Some((0, String::new())));
    }
    #[test]
    fn custom_data_rules() {
        assert!(valid_custom_data("abc123"));
        assert!(!valid_custom_data("has space"));
        assert!(!valid_custom_data("seventeen_chars_x"));
    }
    #[test]
    fn parses_standard_and_interactsh_poll_schemas() {
        let payload = generate(12345, 3, " Login7 ", Some("collab.example.net"));
        let standard_json = r#"{
            "responses": [
                {
                    "interaction_type": "DNS",
                    "client_ip": "203.0.113.9",
                    "timestamp": "2026-11-06T18:50:00Z",
                    "protocol_details": "A query",
                    "comment": "Lookup from backend"
                }
            ]
        }"#;
        let hits = parse_poll_response(standard_json, &payload).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].interaction_type, "DNS");
        assert_eq!(hits[0].client_ip, "203.0.113.9");
        assert_eq!(hits[0].timestamp, "2026-11-06T18:50:00Z");
        assert_eq!(hits[0].protocol_details, "A query");
        assert_eq!(hits[0].comment, "Lookup from backend");
        assert_eq!(hits[0].payload, payload);

        let interactsh_json = r#"{
            "data": [
                {
                    "protocol": "http",
                    "remote-address": "198.51.100.42",
                    "timestamp": "18:51:12",
                    "q-type": "GET /callback HTTP/1.1",
                    "full-id": "customid.collab.example.net"
                }
            ]
        }"#;
        let hits2 = parse_poll_response(interactsh_json, "fallback.collab.example.net").unwrap();
        assert_eq!(hits2.len(), 1);
        assert_eq!(hits2[0].interaction_type, "HTTP");
        assert_eq!(hits2[0].client_ip, "198.51.100.42");
        assert_eq!(hits2[0].timestamp, "18:51:12");
        assert_eq!(hits2[0].payload, "customid.collab.example.net");
        assert_eq!(hits2[0].comment, "GET /callback HTTP/1.1");
    }
    #[test]
    fn poll_all_fetches_interactions_over_http() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let body = r#"{"interactions":[{"type":"HTTP","client_ip":"10.0.0.5","time":"12:34:56","protocol_details":"GET /ssrftest","comment":"SSRF hit"}]}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).unwrap();
            req
        });
        let srv = format!("127.0.0.1:{}", addr.port());
        let payload = generate(42, 1, " Admin ", Some("collab.test"));
        let expected_id = payload_id(&payload).to_string();
        let hits = poll_all(&srv, std::slice::from_ref(&payload), &crate::http::SendOptions::default()).unwrap();
        let req_line = handle.join().unwrap();
        assert!(req_line.starts_with(&format!("GET /poll?id={expected_id} HTTP/1.1")));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].interaction_type, "HTTP");
        assert_eq!(hits[0].client_ip, "10.0.0.5");
        assert_eq!(hits[0].comment, "SSRF hit");
    }
}
