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
    use crate::test_utils::{assert_table, HttpFixture};

    #[test]
    fn payload_generation_and_codec_matrix() {
        // 1. Round-trip generation & decoding matrix across bare IDs, FQDNs, and IP servers
        struct RoundTripCase {
            name: &'static str,
            seed: u64,
            counter: u64,
            custom: &'static str,
            server: Option<&'static str>,
            expected_contains_dot: bool,
            expected_suffix: Option<&'static str>,
            expected_prefix: Option<&'static str>,
            expected_decoded: (u64, &'static str),
        }

        let round_trip_cases = [
            RoundTripCase {
                name: "standard FQDN with mixed-case custom data round-trips lowercased",
                seed: 12345,
                counter: 7,
                custom: "Order42",
                server: Some("collab.example.com"),
                expected_contains_dot: true,
                expected_suffix: Some(".collab.example.com"),
                expected_prefix: None,
                expected_decoded: (7, "order42"),
            },
            RoundTripCase {
                name: "oast.fun domain with empty custom data and high counter",
                seed: 987654321,
                counter: 1024,
                custom: "",
                server: Some("oast.fun"),
                expected_contains_dot: true,
                expected_suffix: Some(".oast.fun"),
                expected_prefix: None,
                expected_decoded: (1024, ""),
            },
            RoundTripCase {
                name: "FQDN with leading/trailing dots and whitespace is normalized",
                seed: 555,
                counter: 19,
                custom: "a1b2c3d4e5f6g7h8",
                server: Some(" .collab.example.net. "),
                expected_contains_dot: true,
                expected_suffix: Some(".collab.example.net"),
                expected_prefix: None,
                expected_decoded: (19, "a1b2c3d4e5f6g7h8"),
            },
            RoundTripCase {
                name: "bare ID when server is None",
                seed: 99,
                counter: 0,
                custom: "",
                server: None,
                expected_contains_dot: false,
                expected_suffix: None,
                expected_prefix: None,
                expected_decoded: (0, ""),
            },
            RoundTripCase {
                name: "bare ID when server is whitespace-only",
                seed: 42,
                counter: 3,
                custom: "token9",
                server: Some("   "),
                expected_contains_dot: false,
                expected_suffix: None,
                expected_prefix: None,
                expected_decoded: (3, "token9"),
            },
            RoundTripCase {
                name: "IPv4 server prepends IP before payload ID",
                seed: 777,
                counter: 12,
                custom: "ipcheck",
                server: Some("10.0.0.5"),
                expected_contains_dot: true,
                expected_suffix: None,
                expected_prefix: Some("10.0.0.5."),
                expected_decoded: (12, "ipcheck"),
            },
        ];

        assert_table!(round_trip_cases, |case| {
            let p = generate(case.seed, case.counter, case.custom, case.server);
            assert_eq!(p.contains('.'), case.expected_contains_dot, "case '{}': {p}", case.name);
            if let Some(suffix) = case.expected_suffix {
                assert!(p.ends_with(suffix), "case '{}': expected suffix '{suffix}' in '{p}'", case.name);
            }
            if let Some(prefix) = case.expected_prefix {
                assert!(p.starts_with(prefix), "case '{}': expected prefix '{prefix}' in '{p}'", case.name);
            }
            let bare = payload_id(&p);
            assert!(!bare.contains('.'), "case '{}': payload_id '{bare}' must be bare", case.name);
            assert_eq!(
                decode(&p),
                Some((case.expected_decoded.0, case.expected_decoded.1.to_string())),
                "case '{}'",
                case.name
            );
            assert_eq!(
                decode(bare),
                Some((case.expected_decoded.0, case.expected_decoded.1.to_string())),
                "case '{}' (bare ID)",
                case.name
            );
        });

        // 2. Custom data validation rules matrix
        let custom_data_cases = [
            ("empty string is valid", "", true),
            ("alphanumeric mixed case is valid", "abc123XYZ", true),
            ("exact 16-char maximum boundary is valid", "a1b2c3d4e5f6g7h8", true),
            ("17-char string exceeding limit is rejected", "a1b2c3d4e5f6g7h89", false),
            ("17-char underscore string is rejected", "seventeen_chars_x", false),
            ("whitespace in custom data is rejected", "has space", false),
            ("hyphen punctuation is rejected", "order-42", false),
            ("non-ASCII alphanumeric is rejected", "caf\u{e9}123", false),
        ];

        assert_table!(custom_data_cases, |(name, input, expected)| {
            assert_eq!(valid_custom_data(input), expected, "{name}: {input:?}");
        });

        // 3. Corrupted & malformed payload decoding resilience matrix
        let valid_bare = generate(12345, 7, "Order42", None);
        let mut tampered_checksum = valid_bare.clone().into_bytes();
        tampered_checksum[PREFIX_LEN] = if tampered_checksum[PREFIX_LEN] == b'a' { b'b' } else { b'a' };
        let tampered_checksum = String::from_utf8(tampered_checksum).unwrap();

        // Build a payload with valid prefix + checksum whose unmasked tail has no 'y' separator
        let prefix_bytes = &valid_bare.as_bytes()[..PREFIX_LEN + 1];
        let no_y_tail: String = (0..6)
            .map(|i| {
                // Seal '0' at every position so unmasked plaintext is "000000" (no 'y')
                let k = keystream(&prefix_bytes[..PREFIX_LEN], i);
                ALPHABET[((idx(b'0').unwrap() + k) % 36) as usize] as char
            })
            .collect();
        let missing_y_payload = format!("{}{no_y_tail}", String::from_utf8_lossy(prefix_bytes));

        // Build a payload with valid prefix + checksum whose counter before 'y' is non-numeric ("ayb")
        let non_numeric_counter_tail: String = b"ayb"
            .iter()
            .enumerate()
            .map(|(i, &ch)| {
                let k = keystream(&prefix_bytes[..PREFIX_LEN], i);
                ALPHABET[((idx(ch).unwrap() + k) % 36) as usize] as char
            })
            .collect();
        let non_numeric_counter_payload = format!("{}{non_numeric_counter_tail}", String::from_utf8_lossy(prefix_bytes));

        let malformed_cases = [
            ("empty string", String::new()),
            ("truncated prefix shorter than PREFIX_LEN + 2", "abc12345".to_string()),
            ("tampered checksum character", tampered_checksum),
            ("invalid uppercase alphabet characters", valid_bare.to_ascii_uppercase()),
            ("invalid punctuation inside token", format!("{}!invalid", &valid_bare[..PREFIX_LEN + 1])),
            ("missing 'y' separator in decrypted plaintext", missing_y_payload),
            ("non-numeric counter before 'y' separator", non_numeric_counter_payload),
        ];

        assert_table!(malformed_cases, |(name, bad_payload)| {
            assert_eq!(decode(&bad_payload), None, "{name}: {bad_payload:?}");
        });
    }

    #[test]
    fn poll_url_matrix() {
        let cases = [
            (
                "bare domain defaults to http:// and /poll?id=",
                "example.com",
                "abc123token",
                "http://example.com/poll?id=abc123token",
            ),
            (
                "explicit https:// scheme preserved",
                "https://custom-collab.net",
                "xyz987",
                "https://custom-collab.net/poll?id=xyz987",
            ),
            (
                "trailing slash and custom port normalized",
                "http://10.0.0.5:8080/",
                "tok42",
                "http://10.0.0.5:8080/poll?id=tok42",
            ),
            (
                "surrounding whitespace and multiple trailing slashes stripped",
                "  https://oast.fun///  ",
                "id7",
                "https://oast.fun/poll?id=id7",
            ),
            (
                "custom endpoint path appends ?id= without duplicating /poll",
                "https://collab.example.com/api/v1/events",
                "tok99",
                "https://collab.example.com/api/v1/events?id=tok99",
            ),
            (
                "custom endpoint path with existing query parameter appends &id=",
                "https://collab.example.com/poll?secret=1",
                "tok99",
                "https://collab.example.com/poll?secret=1&id=tok99",
            ),
        ];

        assert_table!(cases, |(name, server, id, expected)| {
            assert_eq!(poll_url(server, id), expected, "{name}");
        });
    }

    #[test]
    fn collab_interaction_parsing_matrix() {
        let tracked_payload = generate(12345, 3, "Login7", Some("collab.example.net"));

        struct ParseSuccessCase {
            name: &'static str,
            body: &'static str,
            default_payload: String,
            expected: Vec<CollabInteraction>,
        }

        let success_cases = [
            ParseSuccessCase {
                name: "OAST Collaborator standard responses envelope (DNS, HTTP POST, SMTP)",
                body: r#"{
                    "responses": [
                        {
                            "interaction_type": "DNS",
                            "client_ip": "203.0.113.9",
                            "timestamp": "2026-11-06T18:50:00Z",
                            "protocol_details": "A query",
                            "comment": "Lookup from backend"
                        },
                        {
                            "interactionType": "http",
                            "clientIp": "203.0.113.10",
                            "timeStamp": "2026-11-06T18:50:05Z",
                            "protocolDetails": "POST /webhook HTTP/1.1",
                            "interactionId": "explicit.collab.example.net"
                        },
                        {
                            "type": "smtp",
                            "client": "203.0.113.11",
                            "time": "2026-11-06T18:50:10Z",
                            "details": "MAIL FROM:<scanner@example.com>"
                        }
                    ]
                }"#,
                default_payload: tracked_payload.clone(),
                expected: vec![
                    CollabInteraction {
                        interaction_type: "DNS".into(),
                        client_ip: "203.0.113.9".into(),
                        timestamp: "2026-11-06T18:50:00Z".into(),
                        protocol_details: "A query".into(),
                        comment: "Lookup from backend".into(),
                        payload: tracked_payload.clone(),
                    },
                    CollabInteraction {
                        interaction_type: "HTTP".into(),
                        client_ip: "203.0.113.10".into(),
                        timestamp: "2026-11-06T18:50:05Z".into(),
                        protocol_details: "POST /webhook HTTP/1.1".into(),
                        comment: "POST /webhook HTTP/1.1 (Custom data: login7)".into(),
                        payload: "explicit.collab.example.net".into(),
                    },
                    CollabInteraction {
                        interaction_type: "SMTP".into(),
                        client_ip: "203.0.113.11".into(),
                        timestamp: "2026-11-06T18:50:10Z".into(),
                        protocol_details: "MAIL FROM:<scanner@example.com>".into(),
                        comment: "MAIL FROM:<scanner@example.com> (Custom data: login7)".into(),
                        payload: tracked_payload.clone(),
                    },
                ],
            },
            ParseSuccessCase {
                name: "Interactsh data envelope with dns A/AAAA/TXT, http raw-request, and smtp",
                body: r#"{
                    "data": [
                        {
                            "protocol": "dns",
                            "remote-address": "198.51.100.1",
                            "timestamp": "18:51:00",
                            "q-type": "AAAA",
                            "full-id": "sub.oast.fun"
                        },
                        {
                            "protocol": "http",
                            "remote-address": "198.51.100.42",
                            "timestamp": "18:51:12",
                            "raw-request": "R0VUIC9jYWxsYmFjayBIVFRQLzEuMQ==",
                            "full-id": "customid.collab.example.net"
                        },
                        {
                            "protocol": "smtp",
                            "remote_address": "198.51.100.99",
                            "time_stamp": "18:52:00",
                            "raw_request": "RCPT TO:<root@oast.fun>",
                            "unique-id": "smtp1.oast.fun"
                        }
                    ]
                }"#,
                default_payload: "fallback.collab.example.net".into(),
                expected: vec![
                    CollabInteraction {
                        interaction_type: "DNS".into(),
                        client_ip: "198.51.100.1".into(),
                        timestamp: "18:51:00".into(),
                        protocol_details: "AAAA".into(),
                        comment: "AAAA".into(),
                        payload: "sub.oast.fun".into(),
                    },
                    CollabInteraction {
                        interaction_type: "HTTP".into(),
                        client_ip: "198.51.100.42".into(),
                        timestamp: "18:51:12".into(),
                        protocol_details: "R0VUIC9jYWxsYmFjayBIVFRQLzEuMQ==".into(),
                        comment: "R0VUIC9jYWxsYmFjayBIVFRQLzEuMQ==".into(),
                        payload: "customid.collab.example.net".into(),
                    },
                    CollabInteraction {
                        interaction_type: "SMTP".into(),
                        client_ip: "198.51.100.99".into(),
                        timestamp: "18:52:00".into(),
                        protocol_details: "RCPT TO:<root@oast.fun>".into(),
                        comment: "RCPT TO:<root@oast.fun>".into(),
                        payload: "smtp1.oast.fun".into(),
                    },
                ],
            },
            ParseSuccessCase {
                name: "top-level JSON array with missing protocol defaults to DNS and decodes custom data",
                body: r#"[{"ip": "192.0.2.55", "time": "10:00:00"}]"#,
                default_payload: tracked_payload.clone(),
                expected: vec![CollabInteraction {
                    interaction_type: "DNS".into(),
                    client_ip: "192.0.2.55".into(),
                    timestamp: "10:00:00".into(),
                    protocol_details: String::new(),
                    comment: "Custom data: login7".into(),
                    payload: tracked_payload.clone(),
                }],
            },
            ParseSuccessCase {
                name: "empty body or empty JSON object returns empty interaction list",
                body: "   ",
                default_payload: tracked_payload.clone(),
                expected: vec![],
            },
            ParseSuccessCase {
                name: "empty JSON object {} returns empty interaction list",
                body: "{}",
                default_payload: tracked_payload.clone(),
                expected: vec![],
            },
            ParseSuccessCase {
                name: "unknown object fields without interaction fields gracefully return empty list",
                body: r#"{"responses": "not-an-array"}"#,
                default_payload: tracked_payload,
                expected: vec![],
            },
        ];

        assert_table!(success_cases, |case| {
            let actual = parse_poll_response(case.body, &case.default_payload)
                .unwrap_or_else(|e| panic!("case '{}' failed: {e}", case.name));
            assert_eq!(actual, case.expected, "case '{}'", case.name);
        });

        // Malformed poll response bodies must return Err gracefully without panicking
        let malformed_bodies = [
            ("truncated JSON array", r#"{"responses": [{"interaction_type": "DNS""#),
            ("plain text error page", "502 Bad Gateway"),
            ("wrong field type in interaction object", r#"{"type": 123, "responses": "not-an-array"}"#),
            ("wrong field type inside interaction array", r#"[{"interaction_type": 999}]"#),
            ("numeric root JSON value", "42"),
            ("array of primitives instead of objects", "[1, 2, 3]"),
        ];

        assert_table!(malformed_bodies, |(name, bad_body)| {
            let res = parse_poll_response(bad_body, "fallback.oast.fun");
            assert!(res.is_err(), "{name}: expected Err for {bad_body:?}, got {res:?}");
        });
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
            let fixture = HttpFixture::get("127.0.0.1", "/poll").with_response("200 OK", body);
            let resp = format!(
                "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                fixture.status,
                fixture.response_body.len(),
                fixture.response_body
            );
            stream.write_all(resp.as_bytes()).unwrap();
            req
        });
        let srv = format!("127.0.0.1:{}", addr.port());
        let payload = generate(42, 1, "Admin", Some("collab.test"));
        let expected_id = payload_id(&payload).to_string();
        let hits = poll_all(&srv, std::slice::from_ref(&payload), &crate::http::SendOptions::default()).unwrap();
        let req_line = handle.join().unwrap();
        assert!(req_line.starts_with(&format!("GET /poll?id={expected_id} HTTP/1.1")));
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].interaction_type, "HTTP");
        assert_eq!(hits[0].client_ip, "10.0.0.5");
        assert_eq!(hits[0].comment, "SSRF hit");
        assert!(poll_all("   ", &[], &crate::http::SendOptions::default()).is_err());
    }
}
