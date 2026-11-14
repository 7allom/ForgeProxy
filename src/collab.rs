//! Out-of-band Application Security Testing (OAST) payload generator and polling client.
//! Generates unique tracking tokens using prefix hashing and keystream masking
//! to correlate external callbacks to active testing sessions.

const ALPHABET: &[u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";
pub const PREFIX_LEN: usize = 8; // the length of the identifier earlier versions put in front
pub const CUSTOM_DATA_MAX: usize = 16;

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

/// Read (counter, custom data) back from a payload's id, for the payloads earlier versions
/// handed out: they carried their label inside the identifier, where this reads it from, and
/// a project made then still holds them. A payload from a registered session carries no such
/// label -- the session remembers it instead -- and does not decode.
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

/// Read a field a relay may send as an explicit JSON `null` where it could have left the
/// field out instead. `#[serde(default)]` alone covers only a field that is absent: a `null`
/// in its place is a type error that aborts the whole answer, so an empty sequence sent as
/// `null` would otherwise lose every interaction that came alongside it.
fn null_to_default<'de, D, T>(de: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Default + serde::Deserialize<'de>,
{
    Ok(<Option<T> as serde::Deserialize>::deserialize(de)?.unwrap_or_default())
}

/// One out-of-band interaction returned by a relay polling endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CollabInteraction {
    /// The number this interaction is addressed by for as long as it is kept: row selection,
    /// sorting, filtering and the arrow keys all name an interaction by this, so none of them
    /// can come to mean a different one when the table is re-sorted or narrowed. Assigned when
    /// the interaction is taken in; an interaction read from a project saved before ids
    /// existed reads back as 0 and is given one by [`renumber`].
    ///
    /// Written to a project under a name of its own: a relay's `id` is the payload an
    /// interaction fired on, which is what `payload` below reads, not this.
    #[serde(default, rename = "row_id", deserialize_with = "null_to_default")]
    pub id: usize,
    /// Interaction protocol/type ("DNS", "HTTP", "HTTPS", "SMTP").
    #[serde(default, deserialize_with = "null_to_default", alias = "type", alias = "protocol", alias = "interactionType")]
    pub interaction_type: String,
    /// Client IP address that initiated the interaction.
    #[serde(
        default,
        deserialize_with = "null_to_default",
        alias = "client",
        alias = "remote-address",
        alias = "remote_address",
        alias = "source_ip",
        alias = "clientIp",
        alias = "ip"
    )]
    pub client_ip: String,
    /// Interaction timestamp (ISO-8601 / RFC-3339 or server time string).
    #[serde(default, deserialize_with = "null_to_default", alias = "time", alias = "time_stamp", alias = "timeStamp")]
    pub timestamp: String,
    /// Protocol-specific details, as one line for the table: the query type of a lookup, or
    /// the first line of a request. Worked out from the fields below when the server does not
    /// send one of its own.
    #[serde(default, deserialize_with = "null_to_default", alias = "details", alias = "protocolDetails", alias = "query")]
    pub protocol_details: String,
    /// Comment or decoded custom data annotation.
    #[serde(default, deserialize_with = "null_to_default", alias = "custom_data", alias = "customData", alias = "note")]
    pub comment: String,
    /// The payload that was triggered: the whole hostname when the server reports one, and
    /// the identifier alone otherwise. `unique_id` below is the session part of it, which is
    /// what a payload handed out here is matched back by.
    #[serde(default, deserialize_with = "null_to_default", alias = "id", alias = "interaction_id", alias = "interactionId", alias = "full-id", alias = "full_id")]
    pub payload: String,
    /// What a lookup asked for: "A", "AAAA", "TXT". Empty for an interaction that was not one.
    #[serde(default, deserialize_with = "null_to_default", alias = "q-type", alias = "q_type", alias = "queryType")]
    pub query_type: String,
    /// The request as it arrived, whole: the lookup, the HTTP request, the conversation.
    #[serde(default, deserialize_with = "null_to_default", alias = "raw-request", alias = "raw_request", alias = "rawRequest")]
    pub raw_request: String,
    /// What the relay answered it with.
    #[serde(default, deserialize_with = "null_to_default", alias = "raw-response", alias = "raw_response", alias = "rawResponse")]
    pub raw_response: String,
    /// The identifier the relay reported the interaction under, which is the correlation id
    /// and the payload's nonce together.
    #[serde(default, deserialize_with = "null_to_default", alias = "unique-id", alias = "unique_id", alias = "uniqueId")]
    pub unique_id: String,
}

impl CollabInteraction {
    /// The one line the table shows about what happened: what a lookup asked for, or the
    /// first line of the request that came in.
    pub fn summary(&self) -> String {
        if !self.protocol_details.trim().is_empty() {
            return self.protocol_details.trim().to_string();
        }
        if !self.query_type.trim().is_empty() {
            return format!("{} lookup", self.query_type.trim());
        }
        self.raw_request.lines().next().unwrap_or("").trim().to_string()
    }

    /// Is there a message to show in the inspector below the table?
    pub fn has_message(&self) -> bool {
        !self.raw_request.trim().is_empty() || !self.raw_response.trim().is_empty()
    }

    /// Is this the same interaction a relay has already reported? Everything it said is
    /// compared, leaving out the id this app assigns on ingestion -- a freshly polled
    /// interaction has not been given one yet, so comparing that too would let every poll
    /// record the same interactions again.
    pub fn is_same_event(&self, other: &Self) -> bool {
        let (mut a, mut b) = (self.clone(), other.clone());
        a.id = 0;
        b.id = 0;
        a == b
    }
}

/// The protocols a relay is known to report, in the order the filter bar offers them. A relay
/// is free to send anything at all, so this is an ordering and a colour key, never a limit:
/// [`protocols`] lists whatever actually came in, and an unknown protocol sorts after these.
pub const KNOWN_PROTOCOLS: [&str; 9] = ["DNS", "HTTP", "HTTPS", "SMTP", "SMTPS", "LDAP", "FTP", "FTPS", "SMB"];

/// A protocol as the table and the filter bar spell it: trimmed and upper case, so the one
/// pill stands for a relay that says "dns" and a relay that says "DNS". Empty stays empty.
pub fn normalize_protocol(raw: &str) -> String {
    raw.trim().to_ascii_uppercase()
}

/// The id to give the next interaction, one past the highest in use. Ids are never reused, so
/// a selection cannot come to mean a different interaction after a removal.
pub fn next_interaction_id(hits: &[CollabInteraction]) -> usize {
    hits.iter().map(|h| h.id).max().unwrap_or(0) + 1
}

/// Give every interaction an id of its own, for interactions read from a project saved before
/// they had one (they all read back as 0). Interactions that already have distinct ids are
/// left as they are.
pub fn renumber(hits: &mut [CollabInteraction]) {
    let mut seen = std::collections::HashSet::new();
    if hits.iter().all(|h| h.id != 0 && seen.insert(h.id)) {
        return;
    }
    for (i, h) in hits.iter_mut().enumerate() {
        h.id = i + 1;
    }
}

/// The distinct protocols among these interactions, the known ones in the order
/// [`KNOWN_PROTOCOLS`] gives and anything else after them in alphabetical order. This is what
/// the filter bar is built from, so a relay reporting something new gets a pill of its own
/// without a line of code changing.
pub fn protocols(hits: &[CollabInteraction]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for hit in hits {
        let name = normalize_protocol(&hit.interaction_type);
        if !name.is_empty() && !found.iter().any(|f| *f == name) {
            found.push(name);
        }
    }
    let rank = |name: &str| KNOWN_PROTOCOLS.iter().position(|k| *k == name).unwrap_or(KNOWN_PROTOCOLS.len());
    found.sort_by(|a, b| rank(a).cmp(&rank(b)).then_with(|| a.cmp(b)));
    found
}

/// How many of these interactions are of this protocol.
pub fn protocol_count(hits: &[CollabInteraction], protocol: &str) -> usize {
    hits.iter().filter(|h| normalize_protocol(&h.interaction_type) == protocol).count()
}

/// The label the payload behind this interaction was handed out under, or empty when the
/// session never handed out a payload matching it -- an interaction collected by an earlier
/// session, or one for a payload generated without a label.
pub fn label_of(session: Option<&OastSession>, hit: &CollabInteraction) -> String {
    session
        .and_then(|s| s.label_for(&hit.unique_id))
        .map(|p| p.custom_data.clone())
        .unwrap_or_default()
}

/// Which column the interactions table is sorted by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollabSortColumn {
    Index,
    Time,
    Type,
    Payload,
    Label,
    SourceIp,
    Comment,
}

/// What the interactions table shows: the protocol pill that is on, the search box, and the
/// column it is sorted by.
#[derive(Clone, Debug, PartialEq)]
pub struct CollabView {
    /// Matched against an interaction's payload, label, address and comment, ignoring case.
    pub search: String,
    /// The one protocol being shown, or `None` for all of them.
    pub protocol: Option<String>,
    pub sort_column: Option<CollabSortColumn>,
    pub sort_ascending: bool,
}

impl Default for CollabView {
    fn default() -> Self {
        Self {
            search: String::new(),
            protocol: None,
            // the order interactions arrived in, which is what an untouched table shows
            sort_column: Some(CollabSortColumn::Index),
            sort_ascending: true,
        }
    }
}

impl CollabView {
    /// Click on a column header: the same column flips the order, another one sorts by it
    /// ascending. The same rule the traffic tables follow.
    pub fn click_column(&mut self, col: CollabSortColumn) {
        if self.sort_column == Some(col) {
            self.sort_ascending = !self.sort_ascending;
        } else {
            self.sort_column = Some(col);
            self.sort_ascending = true;
        }
    }

    /// Is any filter narrowing what is shown?
    pub fn is_filtering(&self) -> bool {
        !self.search.trim().is_empty() || self.protocol.is_some()
    }

    /// Does this interaction pass the filters?
    pub fn matches(&self, session: Option<&OastSession>, hit: &CollabInteraction) -> bool {
        if let Some(want) = &self.protocol {
            if normalize_protocol(&hit.interaction_type) != *want {
                return false;
            }
        }
        let q = self.search.trim().to_lowercase();
        if q.is_empty() {
            return true;
        }
        let label = label_of(session, hit);
        format!("{} {} {} {} {}", hit.payload, label, hit.client_ip, hit.comment, hit.unique_id).to_lowercase().contains(&q)
    }

    /// Drop a protocol filter whose protocol is no longer among the interactions, so that
    /// clearing the table (or removing the last interaction of a kind) cannot leave the table
    /// filtered to a pill that is not on screen any more and so showing nothing at all.
    pub fn reconcile(&mut self, hits: &[CollabInteraction]) {
        if let Some(want) = &self.protocol {
            if !hits.iter().any(|h| normalize_protocol(&h.interaction_type) == *want) {
                self.protocol = None;
            }
        }
    }
}

/// The rows the table shows, as indices into `hits`: the ones that pass the filters, in the
/// order the sort asks for.
///
/// Every row the table draws comes from here, and a row stands for `hits[index]` however the
/// table is sorted or filtered -- which is what keeps a click on a row, the arrow keys and the
/// detail pane under it all pointing at the same interaction.
pub fn rows(hits: &[CollabInteraction], session: Option<&OastSession>, view: &CollabView) -> Vec<usize> {
    let mut rows: Vec<usize> = hits.iter().enumerate().filter(|(_, h)| view.matches(session, h)).map(|(i, _)| i).collect();
    if let Some(col) = view.sort_column {
        sort_rows(hits, session, &mut rows, col, view.sort_ascending);
    }
    rows
}

/// Sort row indices by `col`, falling back to the order the interactions arrived in so that
/// equal values keep a fixed order whichever way the column is sorted.
fn sort_rows(hits: &[CollabInteraction], session: Option<&OastSession>, rows: &mut [usize], col: CollabSortColumn, ascending: bool) {
    let text = |a: &str, b: &str| a.to_lowercase().cmp(&b.to_lowercase());
    rows.sort_by(|&x, &y| {
        let (a, b) = (&hits[x], &hits[y]);
        let primary = match col {
            CollabSortColumn::Index => a.id.cmp(&b.id),
            CollabSortColumn::Time => text(&a.timestamp, &b.timestamp),
            CollabSortColumn::Type => text(&a.interaction_type, &b.interaction_type),
            CollabSortColumn::Payload => text(&a.payload, &b.payload),
            CollabSortColumn::Label => text(&label_of(session, a), &label_of(session, b)),
            CollabSortColumn::SourceIp => text(&a.client_ip, &b.client_ip),
            CollabSortColumn::Comment => text(&a.comment, &b.comment),
        };
        let primary = if ascending { primary } else { primary.reverse() };
        primary.then(x.cmp(&y))
    });
}

/// Envelope returned by a relay JSON polling endpoint.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CollabPollResponse {
    #[serde(default, deserialize_with = "null_to_default", alias = "responses", alias = "data", alias = "events")]
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
            // a server that reports only the session part of the payload still names the
            // payload that was triggered, as far as it knows one
            if hit.payload.trim().is_empty() && !hit.unique_id.trim().is_empty() {
                hit.payload = hit.unique_id.clone();
            }
            if hit.payload.trim().is_empty() {
                hit.payload = default_payload.to_string();
            }
            if hit.protocol_details.trim().is_empty() {
                hit.protocol_details = hit.summary();
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


// ---- The encrypted relay protocol ---------------------------------------
//
// A public relay hands out one correlation id per session and keeps the interactions it
// sees under it. What it sends back is encrypted to a key only this session holds: the
// session registers an RSA public key, the relay answers each poll with an AES key sealed
// to it, and every interaction is encrypted under that AES key. A relay operator passing
// traffic for other people therefore cannot read what was collected for this one.

/// The relay a new project starts on: empty until the user names one.
pub const DEFAULT_SERVER: &str = "";

/// The size of the session key pair. The relay protocol fixes this.
const KEY_BITS: usize = 2048;

/// How long a correlation id is, and how long the nonce that follows it in a payload. Both
/// are fixed by the protocol: the relay reads the first 20 characters of a hostname's label
/// as the session it belongs to.
const CORRELATION_LEN: usize = 20;
const NONCE_LEN: usize = 13;

/// AES-256 in counter mode, as the relay encrypts each interaction.
type InteractionCipher = ctr::Ctr128BE<aes::Aes256>;

/// A session with a relay: who we are to it, and what it is allowed to tell us.
///
/// The private key never leaves this, and the relay is given only the public half, so the
/// interactions it holds can be read by this session and nothing else. It is kept in a
/// project file so that reopening a project can go on collecting against payloads that are
/// already out in the world.
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct OastSession {
    /// The relay's address, as the user wrote it.
    pub server: String,
    /// 20 lowercase letters and digits: the label the relay reads a hostname's session from.
    pub correlation_id: String,
    /// Proves to the relay that this is the session that registered the correlation id.
    pub secret_key: String,
    /// The session's private key, PKCS#8 PEM. Empty until it has been generated, which
    /// happens off the thread that draws, since it takes a noticeable moment.
    #[serde(default)]
    pub private_key_pem: String,
    /// Payloads handed out under this session, so an interaction can be matched back to the
    /// one that caused it.
    #[serde(default)]
    pub payloads: Vec<GeneratedPayload>,
    /// The relay answered a registration: it speaks the encrypted protocol. A relay that
    /// does not is polled in the plain way instead.
    #[serde(default)]
    pub registered: bool,
}

/// One payload handed out, and what it was labelled with.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct GeneratedPayload {
    /// Correlation id and nonce together: what the relay reports an interaction under.
    pub unique_id: String,
    /// The whole thing as it was copied, host and all.
    pub payload: String,
    /// The custom data that was put in front of it, sanitized.
    #[serde(default)]
    pub custom_data: String,
}

/// Lowercase letters and digits, `n` of them.
fn random_label(n: usize) -> String {
    use rand::RngExt;
    let mut rng = rand::rng();
    (0..n).map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char).collect()
}

/// A version 4 identifier, as the relay expects a secret key to look.
fn random_secret() -> String {
    use rand::RngExt;
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes[..]);
    // the version and variant bits a version 4 identifier carries
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

/// The address of a relay without its scheme or any trailing path.
pub fn server_host(server: &str) -> &str {
    server
        .trim()
        .trim_end_matches('/')
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .trim_matches('.')
}

/// Which scheme to talk to a relay over: the encrypted one, unless the address says
/// otherwise in so many words or names this machine, where there is nothing to protect the
/// traffic from and a certificate would have to be invented.
pub fn server_scheme(server: &str) -> &'static str {
    let trimmed = server.trim();
    if trimmed.starts_with("http://") {
        return "http";
    }
    let host = server_host(trimmed);
    let bare = host.split(':').next().unwrap_or(host);
    if bare.eq_ignore_ascii_case("localhost") || bare == "127.0.0.1" || bare == "[::1]" || bare == "::1" {
        "http"
    } else {
        "https"
    }
}

/// `path` on this relay, with the scheme it is reached over.
fn relay_url(server: &str, path: &str) -> String {
    format!("{}://{}{path}", server_scheme(server), server_host(server))
}

/// Custom data as it can go in a hostname: lowercase letters, digits and hyphens, with
/// nothing else kept and no hyphen left at either end. Empty when there is nothing usable in
/// it, in which case the payload carries no label at all rather than an empty one.
pub fn sanitize_custom_data(s: &str) -> String {
    let kept: String = s
        .trim()
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    // runs of hyphens left by the characters that were dropped read as one
    let mut out = String::new();
    for c in kept.chars() {
        if c == '-' && out.ends_with('-') {
            continue;
        }
        out.push(c);
    }
    out.trim_matches('-').to_string()
}

impl OastSession {
    /// Begin a session: the ids are made here and at once, because a payload can be copied
    /// the moment the tab is open and a payload is nothing without its correlation id. The
    /// key pair and the registration that needs it follow in [`OastSession::prepare`].
    pub fn begin(server: &str) -> Self {
        Self {
            server: server.trim().to_string(),
            correlation_id: random_label(CORRELATION_LEN),
            secret_key: random_secret(),
            private_key_pem: String::new(),
            payloads: Vec::new(),
            registered: false,
        }
    }

    /// Generate the session's key pair. Slow enough to be worth keeping off the drawing
    /// thread -- a few hundred milliseconds, sometimes more.
    pub fn prepare(&mut self) -> Result<(), String> {
        if !self.private_key_pem.is_empty() {
            return Ok(());
        }
        let mut rng = rand::rng();
        let key = rsa::PrivateKey::new(&mut rng, KEY_BITS).map_err(|e| format!("Could not make a session key: {e}"))?;
        self.private_key_pem = rsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(&key, rsa::pkcs8::LineEnding::LF)
            .map_err(|e| format!("Could not store the session key: {e}"))?
            .to_string();
        Ok(())
    }

    /// The session's private key, read back from what is stored.
    fn private_key(&self) -> Result<rsa::PrivateKey, String> {
        if self.private_key_pem.is_empty() {
            return Err("This session has no key yet.".into());
        }
        <rsa::PrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_pem(&self.private_key_pem)
            .map_err(|e| format!("The session key could not be read: {e}"))
    }

    /// The public half, as the relay is given it: a PEM document, base64 again on top.
    fn public_key_field(&self) -> Result<String, String> {
        let key = self.private_key()?;
        let pem = rsa::pkcs8::EncodePublicKey::to_public_key_pem(&key.to_public_key(), rsa::pkcs8::LineEnding::LF)
            .map_err(|e| format!("The session key could not be shared: {e}"))?;
        Ok(crate::codec::base64_encode(pem.as_bytes(), false, true))
    }

    /// A payload to put in a request, and the record of having handed it out.
    ///
    /// `with_server` off leaves the bare identifier, for pasting somewhere that supplies the
    /// relay's address itself.
    pub fn new_payload(&mut self, custom: &str, with_server: bool) -> String {
        let unique_id = format!("{}{}", self.correlation_id, random_label(NONCE_LEN));
        let custom_data = sanitize_custom_data(custom);
        let host = server_host(&self.server);
        let payload = match (custom_data.is_empty(), with_server && !host.is_empty()) {
            (false, true) => format!("{custom_data}.{unique_id}.{host}"),
            (false, false) => format!("{custom_data}.{unique_id}"),
            (true, true) => format!("{unique_id}.{host}"),
            (true, false) => unique_id.clone(),
        };
        self.payloads.push(GeneratedPayload { unique_id, payload: payload.clone(), custom_data });
        payload
    }

    /// What this session called the payload an interaction came in on.
    fn label_for(&self, unique_id: &str) -> Option<&GeneratedPayload> {
        self.payloads.iter().find(|p| !p.unique_id.is_empty() && unique_id.contains(&p.unique_id))
    }
}

/// Why a session could not be registered.
#[derive(Debug, PartialEq, Eq)]
pub enum RegisterError {
    /// The relay answered, but not as one that speaks this protocol: an older or simpler
    /// server, which is polled in the plain way instead.
    NotSupported(String),
    /// It could not be reached, or it refused the registration.
    Failed(String),
}

impl RegisterError {
    pub fn message(&self) -> &str {
        match self {
            Self::NotSupported(m) | Self::Failed(m) => m,
        }
    }
}

/// Register a session with its relay: the public key it may answer to, under the correlation
/// id it will see in hostnames.
pub fn register(session: &OastSession, token: &str, opts: &crate::http::SendOptions) -> Result<(), RegisterError> {
    let body = serde_json::json!({
        "public-key": session.public_key_field().map_err(RegisterError::Failed)?,
        "secret-key": session.secret_key,
        "correlation-id": session.correlation_id,
    })
    .to_string();
    let agent = crate::http::agent(true, opts).map_err(RegisterError::Failed)?;
    let url = relay_url(&session.server, "/register");
    let mut req = agent.post(&url).set("Content-Type", "application/json");
    if let Some(auth) = authorization(token) {
        req = req.set("Authorization", &auth);
    }
    match req.send_string(&body) {
        Ok(_) => Ok(()),
        // a relay that has no registration to offer is one of the plain ones
        Err(ureq::Error::Status(404 | 405 | 501, _)) => Err(RegisterError::NotSupported(format!(
            "{} does not offer an encrypted session; polling it in the plain way.",
            server_host(&session.server)
        ))),
        Err(ureq::Error::Status(401 | 403, _)) => Err(RegisterError::Failed(format!(
            "{} refused the session. Check the server token.",
            server_host(&session.server)
        ))),
        Err(ureq::Error::Status(code, r)) => Err(RegisterError::Failed(format!(
            "{} answered HTTP {code} {} to the registration.",
            server_host(&session.server),
            r.status_text()
        ))),
        Err(ureq::Error::Transport(e)) => Err(RegisterError::Failed(format!(
            "{} could not be reached: {e}",
            server_host(&session.server)
        ))),
    }
}

/// The Authorization header for a relay that wants one, or none at all. A token already
/// carrying its scheme is sent as it was written.
fn authorization(token: &str) -> Option<String> {
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    let first = token.split_whitespace().next().unwrap_or("");
    if first.eq_ignore_ascii_case("bearer") || first.eq_ignore_ascii_case("basic") || first.ends_with(':') {
        Some(token.to_string())
    } else {
        Some(format!("Bearer {token}"))
    }
}

/// What a poll could not do.
#[derive(Debug, PartialEq, Eq)]
pub enum PollError {
    /// The relay has no such session any more: they do not last forever, and one made in a
    /// project opened weeks later will be long gone. A fresh one is registered instead.
    Expired,
    Failed(String),
}

/// The body a relay answers a poll with.
#[derive(serde::Deserialize)]
struct SealedPoll {
    #[serde(default, deserialize_with = "null_to_default")]
    data: Vec<String>,
    #[serde(default, deserialize_with = "null_to_default")]
    extra: Vec<serde_json::Value>,
    #[serde(default, deserialize_with = "null_to_default", rename = "aes_key")]
    aes_key: String,
}

/// Unseal what a relay answered: the AES key is sealed to the session's public key, and each
/// interaction is encrypted under that key with its own initialisation vector in front of it.
pub fn decrypt_interactions(private_key_pem: &str, aes_key_b64: &str, data: &[String]) -> Result<Vec<String>, String> {
    let key = <rsa::PrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_pem(private_key_pem)
        .map_err(|e| format!("The session key could not be read: {e}"))?;
    let sealed = crate::codec::base64_decode(aes_key_b64);
    let aes_key = key
        .decrypt(rsa::Oaep::<rsa::sha2::Sha256>::new(), &sealed)
        .map_err(|e| format!("The key the server sent could not be opened: {e}"))?;
    if aes_key.len() != 32 {
        return Err(format!("The server sent a {}-byte key, not a 256-bit one.", aes_key.len()));
    }
    data.iter()
        .map(|entry| {
            let raw = crate::codec::base64_decode(entry);
            if raw.len() <= 16 {
                return Err("An interaction came back too short to hold anything.".to_string());
            }
            // the first block is the initialisation vector, the rest is the interaction
            let (iv, body) = raw.split_at(16);
            let mut plain = body.to_vec();
            let mut cipher = <InteractionCipher as ctr::cipher::KeyIvInit>::new_from_slices(&aes_key, iv)
                .map_err(|_| "The key the server sent is not the right size.".to_string())?;
            ctr::cipher::StreamCipher::apply_keystream(&mut cipher, &mut plain);
            String::from_utf8(plain).map_err(|_| "An interaction did not come back as text.".to_string())
        })
        .collect()
}

/// One interaction as a relay describes it.
#[derive(serde::Deserialize)]
struct SealedInteraction {
    #[serde(default, deserialize_with = "null_to_default")]
    protocol: String,
    #[serde(default, deserialize_with = "null_to_default", rename = "unique-id")]
    unique_id: String,
    #[serde(default, deserialize_with = "null_to_default", rename = "full-id")]
    full_id: String,
    #[serde(default, deserialize_with = "null_to_default", rename = "q-type")]
    q_type: String,
    #[serde(default, deserialize_with = "null_to_default", rename = "remote-address")]
    remote_address: String,
    #[serde(default, deserialize_with = "null_to_default")]
    timestamp: String,
    #[serde(default, deserialize_with = "null_to_default", rename = "raw-request")]
    raw_request: String,
    #[serde(default, deserialize_with = "null_to_default", rename = "raw-response")]
    raw_response: String,
}

/// Read the interactions out of what a relay sent, in the order it sent them.
fn read_sealed(session: &OastSession, body: &str) -> Result<Vec<CollabInteraction>, String> {
    let sealed: SealedPoll = serde_json::from_str(body.trim()).map_err(|e| format!("The server's answer could not be read: {e}"))?;
    if sealed.data.is_empty() {
        return Ok(Vec::new());
    }
    let opened = decrypt_interactions(&session.private_key_pem, &sealed.aes_key, &sealed.data)?;
    let _ = sealed.extra;
    Ok(opened
        .iter()
        .filter_map(|text| serde_json::from_str::<SealedInteraction>(text).ok())
        .map(|hit| {
            let unique = if hit.unique_id.is_empty() { hit.full_id.clone() } else { hit.unique_id.clone() };
            let mut out = CollabInteraction {
                // given one when it is taken in, by `App::apply_collab_poll`
                id: 0,
                interaction_type: if hit.protocol.trim().is_empty() { "DNS".into() } else { hit.protocol.trim().to_ascii_uppercase() },
                client_ip: hit.remote_address,
                timestamp: hit.timestamp,
                protocol_details: String::new(),
                comment: String::new(),
                payload: if hit.full_id.is_empty() { unique.clone() } else { hit.full_id.clone() },
                query_type: hit.q_type,
                raw_request: hit.raw_request,
                raw_response: hit.raw_response,
                unique_id: unique.clone(),
            };
            out.protocol_details = out.summary();
            if let Some(p) = session.label_for(&unique) {
                if !p.custom_data.is_empty() {
                    out.comment = format!("Custom data: {}", p.custom_data);
                }
            }
            out
        })
        .collect())
}

/// Ask a relay what has come in for this session.
pub fn poll_session(session: &OastSession, token: &str, opts: &crate::http::SendOptions) -> Result<Vec<CollabInteraction>, PollError> {
    let agent = crate::http::agent(true, opts).map_err(PollError::Failed)?;
    let url = format!(
        "{}?id={}&secret={}",
        relay_url(&session.server, "/poll"),
        session.correlation_id,
        session.secret_key
    );
    let mut req = agent.get(&url).set("Accept", "application/json");
    if let Some(auth) = authorization(token) {
        req = req.set("Authorization", &auth);
    }
    match req.call() {
        Ok(r) => {
            let mut raw = Vec::new();
            let _ = std::io::Read::read_to_end(&mut std::io::Read::take(r.into_reader(), crate::http::MAX_BODY), &mut raw);
            let text = String::from_utf8_lossy(&raw).into_owned();
            read_sealed(session, &text).map_err(PollError::Failed)
        }
        // the relay knows nothing of this session: it has expired, or it was registered with
        // a server that has since been restarted
        Err(ureq::Error::Status(400, _)) => Err(PollError::Expired),
        Err(ureq::Error::Status(code, r)) => Err(PollError::Failed(format!(
            "{} answered HTTP {code} {}.",
            server_host(&session.server),
            r.status_text()
        ))),
        Err(ureq::Error::Transport(e)) => Err(PollError::Failed(format!("{} could not be reached: {e}", server_host(&session.server)))),
    }
}

/// What one run of "Poll now" did.
#[derive(Debug)]
pub struct PollRun {
    /// The session it used, when that is not the one it was given: a session registered
    /// because there was none, or because the one there was had expired.
    pub session: Option<OastSession>,
    pub hits: Vec<CollabInteraction>,
    /// Something worth saying about the run that is not a failure -- a relay that turned out
    /// not to speak the encrypted protocol, say.
    pub note: String,
}

/// Collect what has come in: register a session if there is none for this relay, poll it,
/// and register again if the relay has forgotten it. A relay that does not offer sessions at
/// all is polled the plain way, one payload at a time.
pub fn run_poll(
    session: Option<OastSession>,
    server: &str,
    token: &str,
    payloads: &[String],
    opts: &crate::http::SendOptions,
) -> Result<PollRun, String> {
    if server.trim().is_empty() {
        return Err("No Collaborator server set.".into());
    }
    // a session belongs to the relay it was registered with
    let current = session.filter(|s| server_host(&s.server) == server_host(server));
    let (mut session, fresh) = match current {
        Some(s) if s.registered => (s, false),
        Some(s) if !s.private_key_pem.is_empty() => (s, true),
        _ => (OastSession::begin(server), true),
    };
    let mut note = String::new();
    if fresh {
        session.prepare()?;
        match register(&session, token, opts) {
            Ok(()) => session.registered = true,
            Err(RegisterError::NotSupported(m)) => note = m,
            Err(RegisterError::Failed(m)) => return Err(m),
        }
    }
    if !session.registered {
        // a plain relay: the old way, which has no session to keep
        let hits = poll_all(server, payloads, opts)?;
        return Ok(PollRun { session: Some(session), hits, note });
    }
    match poll_session(&session, token, opts) {
        Ok(hits) => Ok(PollRun { session: Some(session), hits, note }),
        Err(PollError::Failed(m)) => Err(m),
        Err(PollError::Expired) => {
            // registered again, under a new correlation id: payloads handed out under the
            // old one are no longer collected, which is what expiry means
            let mut next = OastSession::begin(server);
            next.prepare()?;
            register(&next, token, opts).map_err(|e| e.message().to_string())?;
            next.registered = true;
            let hits = poll_session(&next, token, opts).map_err(|e| match e {
                PollError::Failed(m) => m,
                PollError::Expired => "The server would not keep a session.".to_string(),
            })?;
            Ok(PollRun {
                session: Some(next),
                hits,
                note: "The previous session had expired; a new one was registered.".into(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{assert_table, HttpFixture, MockAppBuilder};

    /// Payloads handed out by earlier versions carried their label inside the identifier.
    /// Projects made then still hold them, so what is read back out of one has to keep
    /// working -- and anything that is not one of them has to be turned down rather than
    /// read as a label that was never there.
    #[test]
    fn a_payload_from_an_earlier_version_still_reads_matrix() {
        // one with a label and a server, one bare: both made by the generator of the time
        assert_eq!(decode("j73yo1chyy2pe7878x.collab.example.com"), Some((7, "order42".to_string())));
        assert_eq!(decode("dz5jyw3ik0m"), Some((3, String::new())));
        assert_eq!(payload_id("j73yo1chyy2pe7878x.collab.example.com"), "j73yo1chyy2pe7878x");

        let cases: [(&str, &str); 6] = [
            ("nothing at all", ""),
            ("too short to hold an identifier", "abc12345"),
            ("a tampered check character", "j73yo1cXyy2pe7878x"),
            ("the wrong case throughout", "J73YO1CHYY2PE7878X"),
            ("punctuation where the label should be", "j73yo1ch!invalid"),
            ("an identifier from a registered session, which carries no label", "k2m9qp4rt7wz0a8bc3xyabcdefghijklm"),
        ];
        assert_table!(cases, |idx, (what, payload)| {
            assert_eq!(decode(payload), None, "case #{idx} ({what}): {payload:?}");
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
                "  https://relay.example.net///  ",
                "id7",
                "https://relay.example.net/poll?id=id7",
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
        // a payload from an earlier version, whose label is read back out of it
        let tracked_payload = "j73yo1chyy2pe7878x.collab.example.com".to_string();

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
                        ..Default::default()
                    },
                    CollabInteraction {
                        interaction_type: "HTTP".into(),
                        client_ip: "203.0.113.10".into(),
                        timestamp: "2026-11-06T18:50:05Z".into(),
                        protocol_details: "POST /webhook HTTP/1.1".into(),
                        comment: "POST /webhook HTTP/1.1 (Custom data: order42)".into(),
                        payload: "explicit.collab.example.net".into(),
                        ..Default::default()
                    },
                    CollabInteraction {
                        interaction_type: "SMTP".into(),
                        client_ip: "203.0.113.11".into(),
                        timestamp: "2026-11-06T18:50:10Z".into(),
                        protocol_details: "MAIL FROM:<scanner@example.com>".into(),
                        comment: "MAIL FROM:<scanner@example.com> (Custom data: order42)".into(),
                        payload: tracked_payload.clone(),
                        ..Default::default()
                    },
                ],
            },
            ParseSuccessCase {
                name: "relay data envelope with dns A/AAAA/TXT, http raw-request, and smtp",
                body: r#"{
                    "data": [
                        {
                            "protocol": "dns",
                            "remote-address": "198.51.100.1",
                            "timestamp": "18:51:00",
                            "q-type": "AAAA",
                            "full-id": "sub.relay.example.net"
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
                            "raw_request": "RCPT TO:<root@relay.example.net>",
                            "unique-id": "smtp1.relay.example.net"
                        }
                    ]
                }"#,
                default_payload: "fallback.collab.example.net".into(),
                // the query type, the request and the identifier now each land in a field
                // of their own, which is what the inspector under the table reads; the one
                // line the table shows is worked out from them
                expected: vec![
                    CollabInteraction {
                        interaction_type: "DNS".into(),
                        client_ip: "198.51.100.1".into(),
                        timestamp: "18:51:00".into(),
                        protocol_details: "AAAA lookup".into(),
                        comment: "AAAA lookup".into(),
                        payload: "sub.relay.example.net".into(),
                        query_type: "AAAA".into(),
                        ..Default::default()
                    },
                    CollabInteraction {
                        interaction_type: "HTTP".into(),
                        client_ip: "198.51.100.42".into(),
                        timestamp: "18:51:12".into(),
                        protocol_details: "R0VUIC9jYWxsYmFjayBIVFRQLzEuMQ==".into(),
                        comment: "R0VUIC9jYWxsYmFjayBIVFRQLzEuMQ==".into(),
                        payload: "customid.collab.example.net".into(),
                        raw_request: "R0VUIC9jYWxsYmFjayBIVFRQLzEuMQ==".into(),
                        ..Default::default()
                    },
                    CollabInteraction {
                        interaction_type: "SMTP".into(),
                        client_ip: "198.51.100.99".into(),
                        timestamp: "18:52:00".into(),
                        protocol_details: "RCPT TO:<root@relay.example.net>".into(),
                        comment: "RCPT TO:<root@relay.example.net>".into(),
                        payload: "smtp1.relay.example.net".into(),
                        raw_request: "RCPT TO:<root@relay.example.net>".into(),
                        unique_id: "smtp1.relay.example.net".into(),
                        ..Default::default()
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
                    comment: "Custom data: order42".into(),
                    payload: tracked_payload.clone(),
                    ..Default::default()
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
            let res = parse_poll_response(bad_body, "fallback.relay.example.net");
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
        let payload = "k2m9qp4rt7wz0a8bc3xy.collab.test".to_string();
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

    // ---- the encrypted relay protocol ----

    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    /// A session with a key pair, ready to register. Generating one takes a moment, so a test
    /// that needs several interactions makes one session and uses it throughout.
    fn session_on(server: &str) -> OastSession {
        let mut s = OastSession::begin(server);
        s.prepare().expect("a session key");
        s
    }

    /// The relay's side of the exchange: seal an AES key to the session's public key, then
    /// encrypt each interaction under it with an initialisation vector of its own. This is
    /// what a relay does, written out here so the reading side can be tested against it.
    fn seal(session: &OastSession, interactions: &[String]) -> (String, Vec<String>) {
        use rand::RngExt;
        let pem = &session.private_key_pem;
        let private = <rsa::PrivateKey as rsa::pkcs8::DecodePrivateKey>::from_pkcs8_pem(pem).expect("the session key");
        let public = private.to_public_key();
        let mut aes_key = [0u8; 32];
        rand::rng().fill(&mut aes_key[..]);
        let sealed_key = public
            .encrypt(&mut rand::rng(), rsa::Oaep::<rsa::sha2::Sha256>::new(), &aes_key)
            .expect("the key seals to the session");
        let data = interactions
            .iter()
            .map(|text| {
                let mut iv = [0u8; 16];
                rand::rng().fill(&mut iv[..]);
                let mut body = text.as_bytes().to_vec();
                let mut cipher = <InteractionCipher as ctr::cipher::KeyIvInit>::new_from_slices(&aes_key, &iv).expect("a cipher");
                ctr::cipher::StreamCipher::apply_keystream(&mut cipher, &mut body);
                let mut whole = iv.to_vec();
                whole.extend_from_slice(&body);
                crate::codec::base64_encode(&whole, false, true)
            })
            .collect();
        (crate::codec::base64_encode(&sealed_key, false, true), data)
    }

    /// One interaction as a relay describes it, for a test to seal.
    fn interaction_json(protocol: &str, unique_id: &str, extra: &str) -> String {
        format!(
            r#"{{"protocol":"{protocol}","unique-id":"{unique_id}","full-id":"{unique_id}","remote-address":"203.0.113.7","timestamp":"2026-11-14T09:30:00Z"{extra}}}"#
        )
    }

    /// What a test relay was asked for, so the test can check it was asked properly.
    #[derive(Default)]
    struct RelayLog {
        register_body: String,
        poll_query: String,
        authorization: String,
    }

    /// A relay that registers one session and answers one poll with `data`, both over plain
    /// HTTP on this machine. `data` is handed the session as it was registered, so it can
    /// seal its answer to the key that was sent.
    fn test_relay(
        answers: impl Fn(&OastSession) -> String + Send + 'static,
        session: OastSession,
    ) -> (String, std::sync::Arc<std::sync::Mutex<RelayLog>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let log = std::sync::Arc::new(std::sync::Mutex::new(RelayLog::default()));
        let seen = log.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten().take(4) {
                let mut stream = stream;
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                let _ = reader.read_line(&mut first);
                let mut length = 0usize;
                let mut auth = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) <= 2 {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            length = v.trim().parse().unwrap_or(0);
                        }
                        if k.trim().eq_ignore_ascii_case("authorization") {
                            auth = v.trim().to_string();
                        }
                    }
                }
                let mut body = vec![0u8; length];
                let _ = reader.read_exact(&mut body);
                let target = first.split_whitespace().nth(1).unwrap_or("").to_string();
                {
                    let mut log = seen.lock().unwrap();
                    if !auth.is_empty() {
                        log.authorization = auth;
                    }
                    if target.starts_with("/register") {
                        log.register_body = String::from_utf8_lossy(&body).into_owned();
                    } else {
                        log.poll_query = target.clone();
                    }
                }
                let answer = if target.starts_with("/register") {
                    "{}".to_string()
                } else {
                    answers(&session)
                };
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}",
                        answer.len()
                    )
                    .as_bytes(),
                );
            }
        });
        (format!("127.0.0.1:{port}"), log)
    }

    fn opts() -> crate::http::SendOptions {
        crate::http::SendOptions { timeout: std::time::Duration::from_secs(5), ..Default::default() }
    }

    /// What a relay sends back is readable by the session that registered and by nothing
    /// else: the key is sealed to the session's public key, and each interaction is
    /// encrypted under it with its own initialisation vector in front.
    #[test]
    fn a_sealed_answer_is_read_back_by_the_session_that_registered_matrix() {
        let session = session_on("relay.test");
        struct Case {
            name: &'static str,
            json: String,
            protocol: &'static str,
            summary: &'static str,
        }
        let cases = [
            Case {
                name: "a lookup",
                json: interaction_json("dns", "abcdefghij0123456789nonce1234", r#","q-type":"A","raw-request":";; opcode: QUERY\n;; QUESTION\nabc.relay.test. IN A","raw-response":";; ANSWER\nabc.relay.test. 60 IN A 203.0.113.1""#),
                protocol: "DNS",
                summary: "A lookup",
            },
            Case {
                name: "a request",
                json: interaction_json("http", "abcdefghij0123456789nonce5678", r#","raw-request":"GET /callback?x=1 HTTP/1.1\nHost: abc.relay.test\n\n","raw-response":"HTTP/1.1 200 OK\n\n<html></html>""#),
                protocol: "HTTP",
                summary: "GET /callback?x=1 HTTP/1.1",
            },
        ];
        assert_table!(cases, |idx, case| {
            let (key, data) = seal(&session, std::slice::from_ref(&case.json));
            let what = format!("case #{idx} ({})", case.name);

            // what the reading side gets back is the interaction, byte for byte
            let opened = decrypt_interactions(&session.private_key_pem, &key, &data).expect("it opens");
            assert_eq!(opened, vec![case.json.clone()], "{what}: the interaction comes back whole");

            // and read into a row of the table, with its message kept for the inspector
            let body = format!(r#"{{"data":{},"extra":[],"aes_key":"{key}"}}"#, serde_json::to_string(&data).unwrap());
            let hits = read_sealed(&session, &body).expect("it reads");
            assert_eq!(hits.len(), 1, "{what}");
            let hit = &hits[0];
            assert_eq!(hit.interaction_type, case.protocol, "{what}: the protocol");
            assert_eq!(hit.client_ip, "203.0.113.7", "{what}: who it came from");
            assert_eq!(hit.timestamp, "2026-11-14T09:30:00Z", "{what}: when");
            assert_eq!(hit.protocol_details, case.summary, "{what}: the line the table shows");
            assert!(hit.has_message(), "{what}: and the message is there to read");
            assert!(hit.raw_request.contains("relay.test") || hit.raw_request.contains("callback"), "{what}: {:?}", hit.raw_request);
            assert!(!hit.raw_response.trim().is_empty(), "{what}: with what was answered");
        });

        // another session cannot read the same answer, which is the point of sealing it
        let (key, data) = seal(&session, &[interaction_json("dns", "x", "")]);
        let stranger = session_on("relay.test");
        assert!(decrypt_interactions(&stranger.private_key_pem, &key, &data).is_err(), "a different session cannot open it");
    }

    /// A relay with nothing to report may write an empty sequence as `null` rather than `[]`.
    /// That has to read as "nothing came in", not as an answer that could not be read: a
    /// `null` alongside a full `data` would otherwise throw away every interaction in it.
    #[test]
    fn a_sealed_answer_tolerates_null_sequences_matrix() {
        let session = session_on("relay.test");
        let json = interaction_json("dns", "abcdefghij0123456789nonce1234", r#","q-type":"A""#);
        let (key, data) = seal(&session, std::slice::from_ref(&json));
        let full = serde_json::to_string(&data).expect("the sealed data");

        let cases: [(&str, String, usize); 6] = [
            ("an empty extra written as null, with interactions to read", format!(r#"{{"data":{full},"extra":null,"aes_key":"{key}"}}"#), 1),
            ("extra left out entirely", format!(r#"{{"data":{full},"aes_key":"{key}"}}"#), 1),
            ("nothing collected, data written as null", format!(r#"{{"data":null,"extra":[],"aes_key":"{key}"}}"#), 0),
            ("both sequences written as null", r#"{"data":null,"extra":null,"aes_key":"k"}"#.to_string(), 0),
            ("neither sequence sent at all", format!(r#"{{"aes_key":"{key}"}}"#), 0),
            ("a key written as null with nothing to open", r#"{"data":null,"extra":null,"aes_key":null}"#.to_string(), 0),
        ];
        assert_table!(cases, |idx, (what, body, want)| {
            let hits = read_sealed(&session, &body).unwrap_or_else(|e| panic!("case #{idx} ({what}) should read, but: {e}"));
            assert_eq!(hits.len(), want, "case #{idx} ({what})");
        });
    }

    /// A relay writes a field it has nothing for as `null`: a lookup carries no response
    /// body, a request carries no query type. One such field must not lose the interaction
    /// it belongs to, which is what dropping the row on a parse error used to do.
    #[test]
    fn a_null_field_inside_a_sealed_interaction_reads_as_empty_matrix() {
        let session = session_on("relay.test");
        let id = "abcdefghij0123456789nonce1234";
        let cases: [(&str, String, &str); 4] = [
            (
                "a lookup with neither request nor response recorded",
                format!(r#"{{"protocol":"dns","unique-id":"{id}","full-id":"{id}","remote-address":"203.0.113.7","timestamp":"2026-11-14T09:30:00Z","q-type":"A","raw-request":null,"raw-response":null}}"#),
                "DNS",
            ),
            (
                "a request with no query type and nothing answered",
                format!(r#"{{"protocol":"http","unique-id":"{id}","full-id":null,"remote-address":"203.0.113.7","timestamp":"2026-11-14T09:30:00Z","q-type":null,"raw-request":"GET /callback HTTP/1.1\nHost: a.relay.test\n\n","raw-response":null}}"#),
                "HTTP",
            ),
            (
                "every field a relay may leave open written as null",
                format!(r#"{{"protocol":null,"unique-id":"{id}","full-id":null,"remote-address":null,"timestamp":null,"q-type":null,"raw-request":null,"raw-response":null}}"#),
                "DNS",
            ),
            (
                "the session named by full-id alone, the rest null",
                format!(r#"{{"protocol":null,"unique-id":null,"full-id":"{id}","remote-address":null,"timestamp":null,"q-type":null,"raw-request":null,"raw-response":null}}"#),
                "DNS",
            ),
        ];
        assert_table!(cases, |idx, (what, json, protocol)| {
            let (key, data) = seal(&session, std::slice::from_ref(&json));
            let body = format!(r#"{{"data":{},"extra":null,"aes_key":"{key}"}}"#, serde_json::to_string(&data).expect("the sealed data"));
            let hits = read_sealed(&session, &body).unwrap_or_else(|e| panic!("case #{idx} ({what}) should read, but: {e}"));
            assert_eq!(hits.len(), 1, "case #{idx} ({what}): a null field must not lose the interaction");
            let hit = &hits[0];
            assert_eq!(hit.unique_id, id, "case #{idx} ({what}): still matched back to its session");
            assert_eq!(hit.interaction_type, protocol, "case #{idx} ({what}): the protocol");
        });
    }

    /// The same for a plain server, which is read without any unsealing: a `null` in place of
    /// a sequence or a string is read as empty rather than failing the whole poll.
    #[test]
    fn a_plain_answer_tolerates_null_fields_matrix() {
        let cases: [(&str, &str, usize); 5] = [
            ("an envelope whose data is null", r#"{"data":null}"#, 0),
            ("an envelope whose responses are null", r#"{"responses":null}"#, 0),
            ("an envelope whose events are null", r#"{"events":null}"#, 0),
            (
                "a row with null strings throughout",
                r#"[{"type":"dns","id":"abcdefghij0123456789nonce1234","q-type":"A","raw-request":null,"raw-response":null,"client":null,"time":null}]"#,
                1,
            ),
            (
                "an envelope of rows, each with null strings",
                r#"{"data":[{"type":null,"id":"abcdefghij0123456789nonce1234","q-type":null,"raw-request":null,"raw-response":null,"client":null,"time":null}]}"#,
                1,
            ),
        ];
        assert_table!(cases, |idx, (what, body, want)| {
            let hits = parse_poll_response(body, "abcdefghij0123456789nonce1234.relay.test")
                .unwrap_or_else(|e| panic!("case #{idx} ({what}) should read, but: {e}"));
            assert_eq!(hits.len(), want, "case #{idx} ({what})");
            for hit in &hits {
                assert_eq!(hit.interaction_type, "DNS", "case #{idx} ({what}): a null protocol falls back to a lookup");
                assert!(hit.raw_request.is_empty() && hit.raw_response.is_empty(), "case #{idx} ({what}): null strings read as empty");
            }
        });
    }

    /// Custom data goes into a hostname, so it has to be a hostname's worth of characters.
    #[test]
    fn custom_data_is_made_safe_for_a_hostname_matrix() {
        let cases: [(&str, &str, &str); 8] = [
            ("letters and digits are kept", "order42", "order42"),
            ("capitals come down", "Order42", "order42"),
            ("spaces become hyphens", "login flow", "login-flow"),
            ("so does anything else", "user@example.com", "user-example-com"),
            ("runs of them read as one", "a///b", "a-b"),
            ("and none is left at either end", "--edge--", "edge"),
            ("nothing usable leaves nothing", "!!!", ""),
            ("nothing at all stays nothing", "   ", ""),
        ];
        assert_table!(cases, |idx, (what, input, want)| {
            assert_eq!(sanitize_custom_data(input), want, "case #{idx} ({what})");
        });
    }

    /// A payload names the session it belongs to, and carries its label in front where a
    /// lookup will show it.
    #[test]
    fn a_payload_names_its_session_matrix() {
        let mut session = OastSession::begin("relay.test");
        let id = session.correlation_id.clone();
        assert_eq!(id.len(), 20, "the correlation id is the length the protocol fixes");
        assert!(id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()), "and is a hostname label: {id}");
        assert_eq!(session.secret_key.len(), 36, "the secret key is a version 4 identifier: {}", session.secret_key);

        let plain = session.new_payload("", true);
        assert_eq!(plain, format!("{}.relay.test", session.payloads[0].unique_id));
        assert!(plain.starts_with(&id), "it opens with the correlation id");
        assert_eq!(session.payloads[0].unique_id.len(), 33, "which the nonce follows");

        let labelled = session.new_payload("Login Flow", true);
        assert_eq!(labelled, format!("login-flow.{}.relay.test", session.payloads[1].unique_id));

        let bare = session.new_payload("", false);
        assert_eq!(bare, session.payloads[2].unique_id, "without the server, the identifier alone");

        // every payload is a session of its own moment: no two are the same
        let ids: std::collections::HashSet<&str> = session.payloads.iter().map(|p| p.unique_id.as_str()).collect();
        assert_eq!(ids.len(), 3, "each payload has a nonce of its own");
        assert!(session.payloads.iter().all(|p| p.unique_id.starts_with(&id)), "and all name the same session");
    }

    /// The whole of it against a relay on this machine: register a session, hand out a
    /// payload, poll, and match what comes back to the payload that caused it.
    #[test]
    fn a_session_registers_hands_out_a_payload_and_collects_what_it_catches() {
        let session = session_on("127.0.0.1");
        let answers = |s: &OastSession| {
            let unique = format!("{}nonce00000000", s.correlation_id);
            let json = interaction_json("http", &unique, r#","raw-request":"GET /hit HTTP/1.1\nHost: x\n\n","raw-response":"HTTP/1.1 200 OK\n\nok""#);
            let (key, data) = seal(s, &[json]);
            format!(r#"{{"data":{},"extra":[],"aes_key":"{key}"}}"#, serde_json::to_string(&data).unwrap())
        };
        let (server, log) = test_relay(answers, session.clone());

        let mut session = OastSession { server: server.clone(), ..session };
        let payload = session.new_payload("Login Flow", true);
        assert!(payload.starts_with("login-flow."), "the label leads the payload: {payload}");
        assert!(payload.ends_with(&server), "and the relay's address closes it: {payload}");

        register(&session, "s3cret", &opts()).expect("the relay takes the registration");
        session.registered = true;

        // the relay was told who to answer, and in the shape the protocol asks for
        let body: serde_json::Value = serde_json::from_str(&log.lock().unwrap().register_body).expect("the registration is JSON");
        assert_eq!(body["correlation-id"], session.correlation_id);
        assert_eq!(body["secret-key"], session.secret_key);
        let public_pem = String::from_utf8(crate::codec::base64_decode(body["public-key"].as_str().unwrap())).unwrap();
        assert!(public_pem.starts_with("-----BEGIN PUBLIC KEY-----"), "the public key goes as a PEM document: {public_pem:?}");
        assert!(!public_pem.contains("PRIVATE"), "and only the public half of it");
        assert_eq!(log.lock().unwrap().authorization, "Bearer s3cret", "a token is sent as it is asked for");

        // the payload that was handed out is on the session, so what comes back is matched
        // to it rather than left anonymous
        session.payloads[0].unique_id = format!("{}nonce00000000", session.correlation_id);
        let hits = poll_session(&session, "s3cret", &opts()).expect("the poll reads");
        let query = log.lock().unwrap().poll_query.clone();
        assert!(query.contains(&format!("id={}", session.correlation_id)), "the poll names the session: {query}");
        assert!(query.contains(&format!("secret={}", session.secret_key)), "and proves it is ours: {query}");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].interaction_type, "HTTP");
        assert_eq!(hits[0].comment, "Custom data: login-flow", "matched back to the payload that caused it");
        assert!(hits[0].raw_request.starts_with("GET /hit"), "with the request it carried");
    }

    /// A simple server that only answers `/poll?id=` is still polled the way it understands,
    /// and a relay that is not there at all is reported rather than waited on.
    #[test]
    fn a_plain_server_is_polled_the_plain_way_and_a_missing_one_is_reported() {
        // a server with no /register to offer, which answers a plain poll
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten().take(4) {
                let mut stream = stream;
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                let _ = reader.read_line(&mut first);
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 2 {
                    line.clear();
                }
                let target = first.split_whitespace().nth(1).unwrap_or("");
                let (code, answer) = if target.starts_with("/register") {
                    (404, "no such thing here".to_string())
                } else {
                    (200, r#"{"data":[{"protocol":"dns","remote-address":"198.51.100.5","timestamp":"09:00:00","q-type":"TXT"}]}"#.to_string())
                };
                let _ = stream.write_all(
                    format!("HTTP/1.1 {code} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}", answer.len()).as_bytes(),
                );
            }
        });
        let server = format!("127.0.0.1:{port}");

        let run = run_poll(None, &server, "", &["abcdefghij0123456789nonce1234".to_string()], &opts()).expect("it falls back rather than failing");
        assert!(run.note.contains("does not offer an encrypted session"), "and says why: {}", run.note);
        let session = run.session.expect("a session is kept for the relay");
        assert!(!session.registered, "which is not a registered one");
        assert_eq!(run.hits.len(), 1, "the interactions came back all the same");
        assert_eq!(run.hits[0].interaction_type, "DNS");
        assert_eq!(run.hits[0].protocol_details, "TXT lookup");

        // and a relay that is not listening at all
        let dead = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let err = run_poll(None, &format!("127.0.0.1:{dead}"), "", &[], &opts()).expect_err("there is nothing there");
        assert!(err.contains("could not be reached"), "{err}");
    }

    /// Which scheme a relay is reached over, and what its address is without the trimmings.
    #[test]
    fn a_relay_is_reached_over_the_right_scheme_matrix() {
        let cases: [(&str, &str, &str, &str); 7] = [
            ("a public relay", "relay.example.com", "https", "relay.example.com"),
            ("one written out in full", "https://relay.example.com/", "https", "relay.example.com"),
            ("plain asked for in so many words", "http://relay.test", "http", "relay.test"),
            ("this machine, where there is nothing to protect", "127.0.0.1:8080", "http", "127.0.0.1:8080"),
            ("and by name", "localhost:9000", "http", "localhost:9000"),
            ("a path is not part of the address", "relay.test/some/path", "https", "relay.test"),
            ("nor are stray dots", ".relay.test.", "https", "relay.test"),
        ];
        assert_table!(cases, |idx, (what, server, scheme, host)| {
            assert_eq!(server_scheme(server), scheme, "case #{idx} ({what})");
            assert_eq!(server_host(server), host, "case #{idx} ({what})");
        });
    }

    /// Three interactions with a different order in every column, and the session that handed
    /// out the payloads they fired on, so the label each one resolves to is a real one.
    fn table_fixture() -> (OastSession, Vec<CollabInteraction>) {
        let mut session = OastSession::begin("relay.test");
        // the label is what the payload was handed out under; the table resolves it back
        // through the session rather than storing it on the interaction
        for custom in ["beta", "gamma", "alpha"] {
            session.new_payload(custom, false);
        }
        let ids: Vec<String> = session.payloads.iter().map(|p| p.unique_id.clone()).collect();
        let hits = vec![
            CollabInteraction {
                id: 1,
                interaction_type: "DNS".into(),
                timestamp: "2026-11-14T09:30:00Z".into(),
                payload: "ccc.relay.test".into(),
                client_ip: "203.0.113.90".into(),
                comment: "zebra".into(),
                unique_id: ids[0].clone(),
                ..Default::default()
            },
            CollabInteraction {
                id: 2,
                interaction_type: "LDAP".into(),
                timestamp: "2026-11-14T08:00:00Z".into(),
                payload: "aaa.relay.test".into(),
                client_ip: "203.0.113.10".into(),
                comment: "middle".into(),
                unique_id: ids[1].clone(),
                ..Default::default()
            },
            CollabInteraction {
                id: 3,
                interaction_type: "HTTP".into(),
                timestamp: "2026-11-14T10:15:00Z".into(),
                payload: "bbb.relay.test".into(),
                client_ip: "203.0.113.50".into(),
                comment: "apple".into(),
                unique_id: ids[2].clone(),
                ..Default::default()
            },
        ];
        (session, hits)
    }

    /// The ids the table shows, in the order it shows them.
    fn shown(hits: &[CollabInteraction], session: &OastSession, view: &CollabView) -> Vec<usize> {
        rows(hits, Some(session), view).iter().map(|&i| hits[i].id).collect()
    }

    /// Every column sorts by what it shows, and clicking the same header again reverses it.
    #[test]
    fn every_column_sorts_by_what_it_shows_matrix() {
        let (session, hits) = table_fixture();
        let cases: [(&str, CollabSortColumn, Vec<usize>); 7] = [
            ("the order they arrived in", CollabSortColumn::Index, vec![1, 2, 3]),
            ("when each came in", CollabSortColumn::Time, vec![2, 1, 3]),
            ("the protocol", CollabSortColumn::Type, vec![1, 3, 2]),
            ("the payload that fired", CollabSortColumn::Payload, vec![2, 3, 1]),
            ("the label the payload was handed out under", CollabSortColumn::Label, vec![3, 1, 2]),
            ("who it came from", CollabSortColumn::SourceIp, vec![2, 3, 1]),
            ("the comment", CollabSortColumn::Comment, vec![3, 2, 1]),
        ];
        assert_table!(cases, |idx, (what, col, ascending)| {
            let mut view = CollabView::default();
            view.sort_column = Some(col);
            view.sort_ascending = true;
            assert_eq!(shown(&hits, &session, &view), ascending, "case #{idx} ({what}): ascending");

            // the same header again turns it round, and nothing else about the view changes
            view.click_column(col);
            assert!(!view.sort_ascending, "case #{idx} ({what}): the same column flips the order");
            let mut reversed = ascending.clone();
            reversed.reverse();
            assert_eq!(shown(&hits, &session, &view), reversed, "case #{idx} ({what}): descending");

            // a different column sorts by that one, ascending again
            view.click_column(CollabSortColumn::Index);
            assert_eq!(view.sort_column, Some(CollabSortColumn::Index), "case #{idx} ({what})");
            assert!(view.sort_ascending, "case #{idx} ({what}): another column starts ascending");
        });
    }

    /// The label on a row is the custom data its payload was handed out under, found through
    /// the session by the identifier the relay reported. An interaction the session never
    /// handed out a payload for has no label rather than someone else's.
    #[test]
    fn a_label_is_resolved_through_the_session_that_handed_the_payload_out() {
        let (session, hits) = table_fixture();
        assert_eq!(label_of(Some(&session), &hits[0]), "beta");
        assert_eq!(label_of(Some(&session), &hits[1]), "gamma");
        assert_eq!(label_of(Some(&session), &hits[2]), "alpha");

        // an interaction for a payload this session never handed out
        let stranger = CollabInteraction { id: 9, unique_id: "someoneelsescorrelation01".into(), ..Default::default() };
        assert_eq!(label_of(Some(&session), &stranger), "", "no label rather than another payload's");
        assert_eq!(label_of(None, &hits[0]), "", "and none at all without a session");
    }

    /// The filter bar is built from what came in: the known protocols in the order the bar
    /// offers them, then anything else a relay chose to send, alphabetically.
    #[test]
    fn the_protocols_offered_are_the_ones_that_came_in() {
        let kinds = ["http", "DNS", "ZZZ-CUSTOM", "SMB", "smtp", "LDAP", "DNS", "Anycast-Thing"];
        let hits: Vec<CollabInteraction> = kinds
            .iter()
            .enumerate()
            .map(|(i, k)| CollabInteraction { id: i + 1, interaction_type: normalize_protocol(k), ..Default::default() })
            .collect();
        assert_eq!(
            protocols(&hits),
            ["DNS", "HTTP", "SMTP", "LDAP", "SMB", "ANYCAST-THING", "ZZZ-CUSTOM"],
            "the known ones in the bar's own order, then whatever else came in"
        );
        assert_eq!(protocol_count(&hits, "DNS"), 2, "a protocol is counted once per interaction");
        assert_eq!(protocol_count(&hits, "ZZZ-CUSTOM"), 1);
        assert_eq!(protocol_count(&hits, "FTP"), 0, "and one that never came in counts none");
        assert!(protocols(&[]).is_empty(), "nothing collected offers nothing to filter by");
    }

    /// A protocol filter and the search box narrow the table together, and the search looks at
    /// everything a row shows.
    #[test]
    fn a_protocol_and_a_search_narrow_the_table_together_matrix() {
        let (session, hits) = table_fixture();
        let cases: [(&str, Option<&str>, &str, Vec<usize>); 8] = [
            ("nothing filtered", None, "", vec![1, 2, 3]),
            ("one protocol", Some("DNS"), "", vec![1]),
            ("a protocol a relay made up is filtered like any other", Some("LDAP"), "", vec![2]),
            ("a protocol nothing came in on", Some("SMB"), "", vec![]),
            ("searching the payload", None, "aaa", vec![2]),
            ("searching the label", None, "alpha", vec![3]),
            ("searching the address", None, "203.0.113.50", vec![3]),
            ("searching the comment", None, "zebra", vec![1]),
        ];
        assert_table!(cases, |idx, (what, protocol, search, want)| {
            let view = CollabView {
                search: search.to_string(),
                protocol: protocol.map(normalize_protocol),
                ..CollabView::default()
            };
            assert_eq!(shown(&hits, &session, &view), want, "case #{idx} ({what})");
            assert_eq!(view.is_filtering(), protocol.is_some() || !search.is_empty(), "case #{idx} ({what})");
        });

        // the two together narrow to what passes both, and to nothing when they disagree
        let both = CollabView { search: "ccc".into(), protocol: Some("DNS".into()), ..CollabView::default() };
        assert_eq!(shown(&hits, &session, &both), [1]);
        let disagree = CollabView { search: "ccc".into(), protocol: Some("HTTP".into()), ..CollabView::default() };
        assert!(shown(&hits, &session, &disagree).is_empty(), "a row has to pass both");
    }

    /// A filter whose protocol is no longer among the interactions is dropped: clearing the
    /// table, or removing the last interaction of a kind, must not leave the table filtered to
    /// a pill that is not there any more and so showing nothing at all.
    #[test]
    fn a_filter_for_a_protocol_that_is_gone_is_dropped() {
        let (_, hits) = table_fixture();
        let mut view = CollabView { protocol: Some("DNS".into()), ..CollabView::default() };
        view.reconcile(&hits);
        assert_eq!(view.protocol.as_deref(), Some("DNS"), "a protocol that is still here stays on");

        // the last DNS interaction goes
        let rest: Vec<CollabInteraction> = hits.iter().filter(|h| h.interaction_type != "DNS").cloned().collect();
        view.reconcile(&rest);
        assert_eq!(view.protocol, None, "the pill it was on is gone, so the filter comes off");

        // and the table being cleared takes any filter with it
        let mut view = CollabView { protocol: Some("HTTP".into()), ..CollabView::default() };
        view.reconcile(&[]);
        assert_eq!(view.protocol, None);
    }

    /// Rows are addressed by an id that is never reused, and interactions read from a project
    /// saved before ids existed are given one on the way in.
    #[test]
    fn ids_are_handed_out_once_and_backfilled_for_an_older_project() {
        let (_, mut hits) = table_fixture();
        assert_eq!(next_interaction_id(&hits), 4, "one past the highest in use");
        assert_eq!(next_interaction_id(&[]), 1, "the first interaction is #1");

        // removing one never lets its id come round again
        hits.retain(|h| h.id != 3);
        assert_eq!(next_interaction_id(&hits), 3, "the highest still held is 2");

        // everything read back as 0: a project saved before interactions had ids
        let mut old: Vec<CollabInteraction> = (0..3).map(|_| CollabInteraction::default()).collect();
        renumber(&mut old);
        assert_eq!(old.iter().map(|h| h.id).collect::<Vec<_>>(), [1, 2, 3], "each is given one of its own");

        // ids that are already distinct are left exactly as they are
        let mut kept = vec![
            CollabInteraction { id: 7, ..Default::default() },
            CollabInteraction { id: 4, ..Default::default() },
        ];
        renumber(&mut kept);
        assert_eq!(kept.iter().map(|h| h.id).collect::<Vec<_>>(), [7, 4], "a project that already had them keeps them");
    }

    /// An interaction already taken in is recognised by what the relay said about it, not by
    /// the id this app gives it -- otherwise every poll would record the same ones again.
    #[test]
    fn the_same_interaction_polled_twice_is_recognised_whatever_id_it_was_given() {
        let (_, hits) = table_fixture();
        let same = CollabInteraction { id: 0, ..hits[0].clone() };
        assert!(hits[0].is_same_event(&same), "the id is not part of what makes it the same event");
        assert!(same.is_same_event(&hits[0]), "whichever way round");

        let renumbered = CollabInteraction { id: 999, ..hits[0].clone() };
        assert!(hits[0].is_same_event(&renumbered));

        // anything the relay actually said differently makes it another interaction
        let elsewhere = CollabInteraction { client_ip: "203.0.113.1".into(), ..hits[0].clone() };
        assert!(!hits[0].is_same_event(&elsewhere), "a different address is a different event");
        assert!(!hits[0].is_same_event(&hits[1]));
    }

    /// Run update frames until `done`, which is what drains the job channel the background
    /// work answers on.
    fn run_frames_until(ctx: &eframe::egui::Context, app: &mut crate::state::App, done: impl Fn(&crate::state::App) -> bool) {
        for _ in 0..600 {
            let _ = ctx.run(eframe::egui::RawInput::default(), |ctx| {
                eframe::App::update(app, ctx, &mut eframe::Frame::_new_kittest())
            });
            if done(app) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("the background work never finished");
    }

    /// Registering a session and polling it is this app talking to its own relay, not traffic
    /// to a target, so none of it belongs in the shared traffic store that the Logger and HTTP
    /// history read. Driven through the very actions the tab uses, against a relay on this
    /// machine, so the store being empty is a fact about the real path and not about a test
    /// that quietly sent nothing.
    #[test]
    fn registering_and_polling_put_nothing_in_the_shared_traffic_store() {
        let session = session_on("127.0.0.1");
        let answers = |s: &OastSession| {
            let unique = format!("{}nonce00000000", s.correlation_id);
            let json = interaction_json("http", &unique, r#","raw-request":"GET /hit HTTP/1.1\nHost: x\n\n","raw-response":"HTTP/1.1 200 OK\n\nok""#);
            let (key, data) = seal(s, &[json]);
            format!(r#"{{"data":{},"extra":[],"aes_key":"{key}"}}"#, serde_json::to_string(&data).unwrap())
        };
        let (server, log) = test_relay(answers, session.clone());

        let (ctx, mut app) = MockAppBuilder::new().with_tab(crate::state::Tab::Collaborator).build_with_ctx();
        let mut session = OastSession { server: server.clone(), ..session };
        let payload = session.new_payload("login", true);
        // the identifier the relay answers under, so what comes back is matched to the payload
        session.payloads[0].unique_id = format!("{}nonce00000000", session.correlation_id);
        app.collab_server = server.clone();
        app.collab_token = "s3cret".into();
        app.collab_payloads.push(payload);
        app.collab_session = Some(session);

        crate::actions::register_collaborator(&mut app);
        run_frames_until(&ctx, &mut app, |a| !a.collab_registering);
        assert!(app.collab_session.as_ref().expect("a session").registered, "the relay took the registration");

        crate::actions::poll_collaborator(&mut app);
        run_frames_until(&ctx, &mut app, |a| !a.collab_polling);
        assert_eq!(app.collab_interactions.len(), 1, "the interaction came back ({})", app.collab_msg);
        assert_eq!(app.collab_interactions[0].interaction_type, "HTTP");

        // the relay really was spoken to, both times
        {
            let seen = log.lock().unwrap();
            assert!(!seen.register_body.is_empty(), "the relay was registered with");
            assert!(!seen.poll_query.is_empty(), "and polled");
        }

        // and none of either exchange was recorded as traffic
        let recorded = app.history.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            recorded.is_empty(),
            "the relay exchange reached the shared traffic store: {:?}",
            recorded.iter().map(|e| format!("{} {}{}", e.tool, e.host, e.path)).collect::<Vec<_>>()
        );
        assert_eq!(*app.next_id.lock().unwrap_or_else(|e| e.into_inner()), 0, "and no entry id was handed out");
    }
}
