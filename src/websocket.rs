//! WebSocket framing (RFC 6455), and what the handshake agreed.
//!
//! The proxy relays a WebSocket connection byte for byte and reads a copy of what goes past,
//! so everything here only ever *takes apart* bytes someone else owns. Nothing in this module
//! writes to a connection, and `next_frame` never consumes more than one whole frame: a frame
//! split across two reads is the ordinary case, not an error.

/// What a frame carries, by its opcode (RFC 6455 §5.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Opcode {
    #[default]
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
    /// An opcode this revision of the protocol does not define. Kept as it was, because the
    /// proxy forwards it unchanged and a reader should see what actually went past.
    Reserved(u8),
}

impl Opcode {
    pub fn from_bits(bits: u8) -> Opcode {
        match bits {
            0x0 => Opcode::Continuation,
            0x1 => Opcode::Text,
            0x2 => Opcode::Binary,
            0x8 => Opcode::Close,
            0x9 => Opcode::Ping,
            0xA => Opcode::Pong,
            other => Opcode::Reserved(other),
        }
    }

    pub fn label(self) -> String {
        match self {
            Opcode::Continuation => "Continuation".into(),
            Opcode::Text => "Text".into(),
            Opcode::Binary => "Binary".into(),
            Opcode::Close => "Close".into(),
            Opcode::Ping => "Ping".into(),
            Opcode::Pong => "Pong".into(),
            Opcode::Reserved(b) => format!("Reserved ({b:#x})"),
        }
    }

    /// Control frames carry their own meaning and are never joined to a message.
    pub fn is_control(self) -> bool {
        matches!(self, Opcode::Close | Opcode::Ping | Opcode::Pong)
            || matches!(self, Opcode::Reserved(b) if b >= 0x8)
    }
}

/// One frame, as read off the wire. `payload` is already unmasked; the bytes the proxy
/// forwards are the original ones, which are never touched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub fin: bool,
    /// Set on the first frame of a message that was compressed (RFC 7692).
    pub rsv1: bool,
    pub opcode: Opcode,
    pub payload: Vec<u8>,
}

/// Which way a message was going.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Direction {
    #[default]
    ClientToServer,
    ServerToClient,
}

impl Direction {
    pub fn label(self) -> &'static str {
        match self {
            Direction::ClientToServer => "To server",
            Direction::ServerToClient => "To client",
        }
    }
}

/// One captured message, as it is kept and as a project file holds it.
///
/// Everything carries a serde default, so a project written by a build with more to say about
/// a message still opens here, and one written here opens in a build that has less.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WsMessage {
    #[serde(default)]
    pub id: usize,
    /// The history entry of the handshake this belongs to, so the two can be shown together.
    #[serde(default)]
    pub entry_id: usize,
    #[serde(default)]
    pub host: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub direction: Direction,
    #[serde(default)]
    pub opcode: Opcode,
    #[serde(default)]
    pub frames: u32,
    #[serde(default)]
    pub compressed: bool,
    /// It ran past the cap and `payload` holds only the start of it.
    #[serde(default)]
    pub truncated: bool,
    /// How long `payload` is in bytes: the message as it reads, so after it was inflated and
    /// after any cut at the cap. Not the number of bytes that went over the wire.
    #[serde(default)]
    pub length: usize,
    /// The payload as text when it is text, and as hex when it is not.
    #[serde(default)]
    pub payload: String,
    /// Unix time in milliseconds.
    #[serde(default)]
    pub time: u64,
}

/// The messages captured so far, shared between the connections recording them and the
/// window showing them.
pub type MessageLog = std::sync::Arc<std::sync::Mutex<Vec<std::sync::Arc<WsMessage>>>>;

/// A connection that is open now, and the way to put a frame onto it.
///
/// The relay owns the sockets, so nothing else may write to them. A message composed in the
/// app is handed over instead, and the relay that owns the connection sends it.
#[derive(Clone, Debug)]
pub struct LiveLink {
    /// The history entry of this connection's handshake.
    pub entry_id: usize,
    pub host: String,
    pub path: String,
    /// When the connection opened: Unix time in milliseconds.
    pub opened: u64,
    pub send: std::sync::mpsc::Sender<Vec<u8>>,
}

/// Every connection the proxy currently has open.
pub type LiveLinks = std::sync::Arc<std::sync::Mutex<Vec<LiveLink>>>;

/// Why a stream of bytes could not be a WebSocket frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameError {
    /// A length this build will not allocate for. The relay keeps forwarding; it just stops
    /// reading a copy of the connection.
    TooLarge(u64),
}

/// The largest single frame payload this build will follow. Four times what a message is
/// ever kept at, so nothing ordinary meets it; a frame past it is not something to keep in a
/// capture, and the relay goes on forwarding it regardless. It also bounds what a peer can
/// make the reader hold: a frame is accumulated until it is whole, so this is the most one
/// direction of one connection can be sitting on.
pub const MAX_FRAME: u64 = 4 * 1024 * 1024;

/// The next whole frame in `buf`, and how many bytes of `buf` it used.
///
/// `Ok(None)` means the buffer holds the start of a frame but not all of it: read more and
/// ask again. The caller keeps the unused tail.
pub fn next_frame(buf: &[u8]) -> Result<Option<(Frame, usize)>, FrameError> {
    // the two bytes every frame starts with
    if buf.len() < 2 {
        return Ok(None);
    }
    let fin = buf[0] & 0x80 != 0;
    let rsv1 = buf[0] & 0x40 != 0;
    let opcode = Opcode::from_bits(buf[0] & 0x0F);
    let masked = buf[1] & 0x80 != 0;

    // the length, in one of its three forms
    let short = buf[1] & 0x7F;
    let (length, mut at) = match short {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            (u64::from(u16::from_be_bytes([buf[2], buf[3]])), 4)
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            let mut n = [0u8; 8];
            n.copy_from_slice(&buf[2..10]);
            (u64::from_be_bytes(n), 10)
        }
        n => (u64::from(n), 2),
    };
    if length > MAX_FRAME {
        return Err(FrameError::TooLarge(length));
    }

    let key = if masked {
        if buf.len() < at + 4 {
            return Ok(None);
        }
        let key = [buf[at], buf[at + 1], buf[at + 2], buf[at + 3]];
        at += 4;
        Some(key)
    } else {
        None
    };

    let length = length as usize;
    let end = at + length;
    if buf.len() < end {
        return Ok(None);
    }
    // unmasked into a copy: the bytes the proxy forwards keep their mask
    let payload = match key {
        Some(key) => buf[at..end].iter().enumerate().map(|(i, b)| b ^ key[i % 4]).collect(),
        None => buf[at..end].to_vec(),
    };
    Ok(Some((Frame { fin, rsv1, opcode, payload }, end)))
}

/// The value a server must answer a handshake with: the client's key, the fixed string the
/// protocol names, hashed and base64'd (RFC 6455 §4.2.2). The proxy checks it only to say so
/// in the event log -- the browser is the one that decides whether to go on.
pub fn accept_key(client_key: &str) -> String {
    use sha1::Digest;
    /// The fixed string the protocol appends before hashing (RFC 6455 §1.3).
    const HANDSHAKE_SUFFIX: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut h = sha1::Sha1::new();
    h.update(client_key.trim().as_bytes());
    h.update(HANDSHAKE_SUFFIX.as_bytes());
    crate::codec::base64_encode(&h.finalize(), false, true)
}

/// What the handshake agreed about compression (RFC 7692).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Negotiated {
    /// The payload compression extension was offered and accepted.
    pub deflate: bool,
    /// Each direction either keeps its compression window between messages or starts afresh.
    pub client_no_context_takeover: bool,
    pub server_no_context_takeover: bool,
}

/// What the two handshake heads agreed. Only what the *response* accepted counts: a client
/// may offer an extension the server never takes up.
pub fn negotiated(response_head: &str) -> Negotiated {
    let accepted = response_head
        .lines()
        .take_while(|l| !l.trim().is_empty())
        .filter_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.trim().eq_ignore_ascii_case("sec-websocket-extensions").then(|| v.trim().to_ascii_lowercase())
        })
        .collect::<Vec<_>>()
        .join(",");
    let has = |p: &str| accepted.split(&[',', ';'][..]).any(|t| t.trim() == p);
    if !has("permessage-deflate") {
        return Negotiated::default();
    }
    Negotiated {
        deflate: true,
        client_no_context_takeover: has("client_no_context_takeover"),
        server_no_context_takeover: has("server_no_context_takeover"),
    }
}

/// The largest message joined back together for reading. A message past this is recorded as
/// what there was of it and marked short; the relay goes on forwarding all of it either way.
pub const MAX_MESSAGE: usize = 1024 * 1024;

/// One whole message: a frame that stood alone, a run of fragments joined back up, or a
/// control frame, which is always its own message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub opcode: Opcode,
    pub payload: Vec<u8>,
    /// How many frames carried it.
    pub frames: u32,
    /// It arrived compressed (RSV1 on its first frame).
    pub compressed: bool,
    /// It ran past `MAX_MESSAGE`, and `payload` holds only the start of it.
    pub truncated: bool,
}

/// Joins fragmented frames back into messages, one per direction of a connection.
///
/// It also undoes the payload compression when the handshake agreed to it. The window a
/// compressed connection uses is shared across its messages unless the handshake said
/// otherwise, so the state belongs here, for the life of the direction.
#[derive(Default)]
pub struct Reassembler {
    /// The message being built, when a fragment has opened one.
    partial: Option<Message>,
    /// Present when this direction was compressed.
    inflate: Option<flate2::Decompress>,
    /// The window starts afresh for every message rather than carrying on.
    no_context_takeover: bool,
}

impl Reassembler {
    /// One side of a connection. `deflate` and `no_context_takeover` are what the handshake
    /// agreed for *this* direction.
    pub fn new(deflate: bool, no_context_takeover: bool) -> Self {
        Reassembler {
            partial: None,
            // raw deflate: the protocol's compression carries no zlib wrapper
            inflate: deflate.then(|| flate2::Decompress::new(false)),
            no_context_takeover,
        }
    }

    /// Take one frame. Returns a message when this frame finished one.
    pub fn push(&mut self, frame: Frame) -> Option<Message> {
        // a control frame is never joined to anything, and may arrive between the fragments
        // of a message that is still being built. RFC 7692 forbids compressing one, so RSV1
        // on it is not a claim to believe: taking it at face value would push the frame
        // through the window this direction shares and spoil every message after it.
        if frame.opcode.is_control() {
            return Some(Message {
                opcode: frame.opcode,
                payload: frame.payload,
                frames: 1,
                compressed: false,
                truncated: false,
            });
        }
        let fin = frame.fin;
        let building = match (&mut self.partial, frame.opcode) {
            // a fragment continuing what is already open
            (Some(open), Opcode::Continuation) => open,
            // anything else opens a message: a new data frame, or a continuation with nothing
            // open, which a peer should not send and which is kept rather than dropped
            _ => self.partial.insert(Message {
                opcode: if frame.opcode == Opcode::Continuation { Opcode::Binary } else { frame.opcode },
                payload: Vec::new(),
                frames: 0,
                compressed: frame.rsv1,
                truncated: false,
            }),
        };
        building.frames += 1;
        let room = MAX_MESSAGE.saturating_sub(building.payload.len());
        if frame.payload.len() > room {
            building.truncated = true;
        }
        building.payload.extend_from_slice(&frame.payload[..room.min(frame.payload.len())]);
        let done = fin.then(|| self.partial.take()).flatten();
        done.map(|m| self.inflate_message(m))
    }

    /// Undo the compression on a finished message.
    ///
    /// Two things make this more than one call. The decompressor only ever writes into the
    /// room the output vector already has, so a single guess at the size would quietly cut a
    /// message short; and the window is shared with every later message in this direction, so
    /// stopping early -- or carrying on after a failure -- would turn all of them to rubbish.
    /// The input is therefore fed through to the end whatever happens, and the window is
    /// reset when it cannot be.
    ///
    /// What is *kept* is capped: a small compressed payload can inflate to an enormous one,
    /// and a capture is not worth a gigabyte of memory. Inflating continues past the cap so
    /// the window stays in step; only the keeping stops.
    fn inflate_message(&mut self, mut m: Message) -> Message {
        if !m.compressed {
            return m;
        }
        let Some(inflate) = self.inflate.as_mut() else { return m };
        if self.no_context_takeover {
            inflate.reset(false);
        }
        // a message already cut short at the cap is an incomplete deflate stream: feeding it
        // in would leave the window holding half a message
        if m.truncated {
            inflate.reset(false);
            return m;
        }
        // the sender drops the four bytes that end a sync flush; the reader puts them back
        let mut input = std::mem::take(&mut m.payload);
        input.extend_from_slice(&[0x00, 0x00, 0xFF, 0xFF]);

        /// How much room to offer the decompressor each time round.
        const CHUNK: usize = 32 * 1024;
        let mut kept: Vec<u8> = Vec::new();
        let mut scratch: Vec<u8> = Vec::new();
        let mut consumed = 0usize;
        let mut over_cap = false;
        let failed = loop {
            scratch.clear();
            scratch.reserve(CHUNK);
            let (was_in, was_out) = (inflate.total_in(), inflate.total_out());
            let outcome = inflate.decompress_vec(&input[consumed..], &mut scratch, flate2::FlushDecompress::Sync);
            let used = (inflate.total_in() - was_in) as usize;
            let made = (inflate.total_out() - was_out) as usize;
            consumed += used;
            let room = MAX_MESSAGE.saturating_sub(kept.len());
            kept.extend_from_slice(&scratch[..room.min(scratch.len())]);
            over_cap |= scratch.len() > room;
            match outcome {
                Err(_) => break true,
                // everything in, and the last round had room to spare: there is no more
                Ok(_) if consumed >= input.len() && made < CHUNK => break false,
                // neither taken nor given: it will not finish, so do not spin on it
                Ok(_) if used == 0 && made == 0 => break true,
                Ok(_) => {}
            }
        };
        if failed {
            // never carry a half-fed window into the next message
            inflate.reset(false);
            input.truncate(input.len().saturating_sub(4));
            m.payload = input;
            return m;
        }
        m.truncated |= over_cap;
        m.payload = kept;
        m
    }
}

/// Build a frame to send. `mask` is required of anything a client sends (RFC 6455 §5.3) and
/// forbidden of anything a server sends, so the caller says which end it is speaking as.
pub fn encode(opcode: Opcode, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
    let bits = match opcode {
        Opcode::Continuation => 0x0,
        Opcode::Text => 0x1,
        Opcode::Binary => 0x2,
        Opcode::Close => 0x8,
        Opcode::Ping => 0x9,
        Opcode::Pong => 0xA,
        Opcode::Reserved(b) => b & 0x0F,
    };
    // whole in one frame: nothing here has a reason to fragment what it sends
    let mut out = vec![0x80 | bits];
    let masked = u8::from(mask.is_some()) << 7;
    match payload.len() {
        n if n <= 125 => out.push(masked | n as u8),
        n if n <= 0xFFFF => {
            out.push(masked | 126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(masked | 127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    match mask {
        Some(key) => {
            out.extend_from_slice(&key);
            out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        }
        None => out.extend_from_slice(payload),
    }
    out
}

/// A masking key with no pattern to it, for a frame sent as a client.
pub fn masking_key() -> [u8; 4] {
    use rand::RngExt;
    let mut key = [0u8; 4];
    rand::rng().fill(&mut key[..]);
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a frame the way a peer would send one.
    fn frame_bytes(fin: bool, rsv1: bool, opcode: u8, payload: &[u8], mask: Option<[u8; 4]>) -> Vec<u8> {
        let mut out = vec![(u8::from(fin) << 7) | (u8::from(rsv1) << 6) | opcode];
        let masked = u8::from(mask.is_some()) << 7;
        match payload.len() {
            n if n <= 125 => out.push(masked | n as u8),
            n if n <= 0xFFFF => {
                out.push(masked | 126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(masked | 127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        match mask {
            Some(key) => {
                out.extend_from_slice(&key);
                out.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
            }
            None => out.extend_from_slice(payload),
        }
        out
    }

    /// The example the protocol itself gives, so the hashing and the encoding are checked
    /// against something outside this codebase.
    #[test]
    fn the_handshake_answer_matches_the_protocols_own_example() {
        assert_eq!(accept_key("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn compression_is_read_from_what_the_server_accepted() {
        use crate::test_utils::assert_table;
        assert_table!(
            [
                ("nothing accepted", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
                 Negotiated::default()),
                ("accepted plainly", "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
                 Negotiated { deflate: true, ..Default::default() }),
                ("both windows reset each message",
                 "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Extensions: permessage-deflate; client_no_context_takeover; server_no_context_takeover\r\n\r\n",
                 Negotiated { deflate: true, client_no_context_takeover: true, server_no_context_takeover: true }),
                ("some other extension", "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Extensions: something-else\r\n\r\n",
                 Negotiated::default()),
            ],
            |idx, (what, head, want)| {
                assert_eq!(negotiated(head), want, "case #{idx} ({what})");
            }
        );
    }

    #[test]
    fn fragments_are_joined_back_into_one_message() {
        let mut r = Reassembler::default();
        assert_eq!(r.push(Frame { fin: false, rsv1: false, opcode: Opcode::Text, payload: b"he".to_vec() }), None);
        assert_eq!(r.push(Frame { fin: false, rsv1: false, opcode: Opcode::Continuation, payload: b"ll".to_vec() }), None);
        let done = r.push(Frame { fin: true, rsv1: false, opcode: Opcode::Continuation, payload: b"o".to_vec() })
            .expect("the last fragment finishes it");
        assert_eq!(done.payload, b"hello".to_vec());
        assert_eq!((done.opcode, done.frames), (Opcode::Text, 3), "it keeps the kind it opened with");
    }

    /// A control frame may arrive between the fragments of a message, and is its own message.
    #[test]
    fn a_control_frame_between_fragments_does_not_join_the_message() {
        let mut r = Reassembler::default();
        r.push(Frame { fin: false, rsv1: false, opcode: Opcode::Text, payload: b"a".to_vec() });
        let ping = r.push(Frame { fin: true, rsv1: false, opcode: Opcode::Ping, payload: b"p".to_vec() })
            .expect("a ping is a message of its own");
        assert_eq!((ping.opcode, ping.payload.as_slice(), ping.frames), (Opcode::Ping, b"p".as_slice(), 1));
        let done = r.push(Frame { fin: true, rsv1: false, opcode: Opcode::Continuation, payload: b"b".to_vec() })
            .expect("and the message carries on around it");
        assert_eq!(done.payload, b"ab".to_vec());
    }

    #[test]
    fn a_message_past_the_cap_is_kept_as_far_as_it_goes_and_marked_short() {
        let mut r = Reassembler::default();
        r.push(Frame { fin: false, rsv1: false, opcode: Opcode::Binary, payload: vec![0u8; MAX_MESSAGE] });
        let done = r.push(Frame { fin: true, rsv1: false, opcode: Opcode::Continuation, payload: vec![1u8; 4096] })
            .expect("it still finishes");
        assert!(done.truncated, "and says it was cut short");
        assert_eq!(done.payload.len(), MAX_MESSAGE, "with no more than the cap kept");
    }

    /// Deflate a payload the way the compression extension says to: a sync flush, with the
    /// four bytes that end one taken off (RFC 7692 §7.2.1).
    fn deflate(data: &[u8], with: &mut flate2::Compress) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 64);
        with.compress_vec(data, &mut out, flate2::FlushCompress::Sync).expect("deflates");
        // the sync flush always ends 00 00 FF FF, and the sender drops it
        assert!(out.ends_with(&[0x00, 0x00, 0xFF, 0xFF]), "{out:?}");
        out.truncate(out.len() - 4);
        out
    }

    /// A compressed message has to be readable, and the relay has to keep forwarding whether
    /// it can read it or not.
    #[test]
    fn a_compressed_message_is_inflated_for_reading() {
        let mut deflater = flate2::Compress::new(flate2::Compression::default(), false);
        let body = b"{\"type\":\"data\",\"payload\":{\"ticks\":[1,2,3]}}";
        let squashed = deflate(body, &mut deflater);

        let mut r = Reassembler::new(true, false);
        let done = r
            .push(Frame { fin: true, rsv1: true, opcode: Opcode::Text, payload: squashed })
            .expect("one frame, one message");
        assert_eq!(done.payload, body.to_vec(), "it reads as what was sent");
        assert!(done.compressed, "and still says it arrived compressed");
    }

    /// With the window kept between messages, a later message leans on what an earlier one
    /// put in it: inflating the second alone would not work.
    #[test]
    fn a_kept_compression_window_carries_between_messages() {
        let mut deflater = flate2::Compress::new(flate2::Compression::default(), false);
        let first = b"the quick brown fox jumps over the lazy dog";
        let second = b"the quick brown fox jumps over the lazy dog again";
        let one = deflate(first, &mut deflater);
        let two = deflate(second, &mut deflater);
        assert!(two.len() < one.len(), "the second leans on the first: {} vs {}", two.len(), one.len());

        let mut r = Reassembler::new(true, false);
        let a = r.push(Frame { fin: true, rsv1: true, opcode: Opcode::Text, payload: one }).expect("first");
        let b = r.push(Frame { fin: true, rsv1: true, opcode: Opcode::Text, payload: two }).expect("second");
        assert_eq!(a.payload, first.to_vec());
        assert_eq!(b.payload, second.to_vec(), "the window was kept, so the second reads too");
    }

    /// Highly compressible text deflates to a tiny fraction of itself, so any fixed guess at
    /// how much room the inflated copy needs will be far too small. Getting this wrong cuts
    /// the message short *and* leaves the shared window out of step, so everything after it
    /// in that direction decodes to rubbish too.
    #[test]
    fn a_message_that_inflates_many_times_over_is_not_cut_short() {
        let mut deflater = flate2::Compress::new(flate2::Compression::default(), false);
        let body = "{\"event\":\"tick\",\"value\":1}".repeat(4000); // ~100 KB, deflates tiny
        let squashed = deflate(body.as_bytes(), &mut deflater);
        assert!(squashed.len() * 4 < body.len(), "the point of the test: {} vs {}", squashed.len(), body.len());

        let mut r = Reassembler::new(true, false);
        let done = r
            .push(Frame { fin: true, rsv1: true, opcode: Opcode::Text, payload: squashed })
            .expect("a message");
        assert_eq!(done.payload.len(), body.len(), "all of it was inflated, not the first few KB");
        assert_eq!(done.payload, body.as_bytes(), "and it is what was sent");

        // and the window is still in step, so the next message reads too
        let next = "{\"event\":\"tick\",\"value\":2}".repeat(4000);
        let more = deflate(next.as_bytes(), &mut deflater);
        let after = r
            .push(Frame { fin: true, rsv1: true, opcode: Opcode::Text, payload: more })
            .expect("another message");
        assert_eq!(after.payload, next.as_bytes(), "the window carried on cleanly");
    }

    /// A message cut off at the cap hands the inflater an incomplete stream. The window it
    /// shares with later messages must not be left holding that.
    #[test]
    fn a_broken_compressed_message_does_not_spoil_the_ones_after_it() {
        let mut r = Reassembler::new(true, false);
        let rubbish = r
            .push(Frame { fin: true, rsv1: true, opcode: Opcode::Text, payload: vec![0xFFu8; 64] })
            .expect("a message");
        assert_eq!(rubbish.payload, vec![0xFFu8; 64], "what would not inflate is kept as it came");

        let mut deflater = flate2::Compress::new(flate2::Compression::default(), false);
        let body = b"a real message, after the broken one";
        let good = deflate(body, &mut deflater);
        let after = r
            .push(Frame { fin: true, rsv1: true, opcode: Opcode::Text, payload: good })
            .expect("another message");
        assert_eq!(after.payload, body.to_vec(), "the next message still reads");
    }

    /// A control frame carries no compressed payload: RFC 7692 forbids it. Taking RSV1 on one
    /// at face value would push it through the shared window and spoil it.
    #[test]
    fn a_control_frame_is_never_treated_as_compressed() {
        let mut r = Reassembler::new(true, false);
        let ping = r
            .push(Frame { fin: true, rsv1: true, opcode: Opcode::Ping, payload: b"hello".to_vec() })
            .expect("a ping");
        assert!(!ping.compressed, "a control frame is never compressed");
        assert_eq!(ping.payload, b"hello".to_vec(), "and its payload is untouched");
    }

    /// A payload that will not inflate is shown as it arrived rather than losing the message.
    #[test]
    fn a_payload_that_will_not_inflate_is_kept_as_it_came() {
        let mut r = Reassembler::new(true, false);
        let rubbish = vec![0xFFu8; 32];
        let done = r
            .push(Frame { fin: true, rsv1: true, opcode: Opcode::Binary, payload: rubbish.clone() })
            .expect("still a message");
        assert_eq!(done.payload, rubbish, "nothing was lost");
    }

    #[test]
    fn a_compressed_message_says_so() {
        let mut r = Reassembler::default();
        let done = r.push(Frame { fin: true, rsv1: true, opcode: Opcode::Text, payload: b"..".to_vec() }).expect("one frame");
        assert!(done.compressed);
    }

    /// What is built has to be what is read: the parser is the only check the builder gets.
    #[test]
    fn a_built_frame_reads_back_as_itself() {
        use crate::test_utils::assert_table;
        assert_table!(
            [
                ("text, as a client sends it", Opcode::Text, b"hello".to_vec(), true),
                ("binary, as a client sends it", Opcode::Binary, vec![0u8, 255, 7], true),
                ("text, as a server sends it", Opcode::Text, b"hello".to_vec(), false),
                ("empty", Opcode::Text, Vec::new(), true),
                ("past the 7-bit length", Opcode::Binary, vec![3u8; 300], true),
                ("past the 16-bit length", Opcode::Binary, vec![4u8; 70_000], false),
                ("a ping", Opcode::Ping, b"are you there".to_vec(), true),
            ],
            |idx, (what, opcode, payload, as_client)| {
                let mask = as_client.then(masking_key);
                let bytes = encode(opcode, &payload, mask);
                let (frame, used) = next_frame(&bytes).expect("it parses").unwrap_or_else(|| panic!("case #{idx} ({what}): incomplete"));
                assert_eq!(used, bytes.len(), "case #{idx} ({what}): used all of it");
                assert_eq!(frame.payload, payload, "case #{idx} ({what})");
                assert_eq!(frame.opcode, opcode, "case #{idx} ({what})");
                assert!(frame.fin, "case #{idx} ({what}): sent whole");
                if as_client && !payload.is_empty() {
                    assert_ne!(&bytes[bytes.len() - payload.len()..], payload.as_slice(), "case #{idx} ({what}): it was masked on the wire");
                }
            }
        );
    }

    /// A key that repeated would make a client's frames guessable.
    #[test]
    fn masking_keys_are_not_all_the_same() {
        let keys: std::collections::HashSet<[u8; 4]> = (0..32).map(|_| masking_key()).collect();
        assert!(keys.len() > 1, "a fresh key each time");
    }

    #[test]
    fn a_server_frame_is_read_whole() {
        let bytes = frame_bytes(true, false, 0x1, b"hello", None);
        let (frame, used) = next_frame(&bytes).expect("a frame").expect("all of it is there");
        assert_eq!(used, bytes.len(), "it used exactly its own bytes");
        assert_eq!(
            frame,
            Frame { fin: true, rsv1: false, opcode: Opcode::Text, payload: b"hello".to_vec() },
        );
    }

    /// Everything a client sends is masked (RFC 6455 §5.3). The payload is only readable once
    /// the mask is taken off a copy of it.
    #[test]
    fn a_client_frame_is_unmasked() {
        let bytes = frame_bytes(true, false, 0x1, b"hello", Some([0x37, 0xfa, 0x21, 0x3d]));
        let (frame, used) = next_frame(&bytes).expect("a frame").expect("all of it is there");
        assert_eq!(used, bytes.len());
        assert_eq!(frame.payload, b"hello".to_vec(), "the mask came off");
        assert_ne!(&bytes[6..], b"hello", "and the bytes on the wire were masked");
    }

    /// A read returns whatever arrived, which is routinely less than a frame, or more than one.
    #[test]
    fn a_frame_split_across_reads_waits_for_the_rest() {
        let bytes = frame_bytes(true, false, 0x2, &[7u8; 200], None);
        for cut in [0, 1, 2, 3, 50, bytes.len() - 1] {
            assert_eq!(next_frame(&bytes[..cut]), Ok(None), "cut at {cut}: not all there yet");
        }
        let (frame, used) = next_frame(&bytes).expect("a frame").expect("now it is");
        assert_eq!((used, frame.payload.len()), (bytes.len(), 200));
    }

    #[test]
    fn the_tail_after_a_frame_is_left_for_the_next_one() {
        let mut bytes = frame_bytes(true, false, 0x1, b"one", None);
        let second = frame_bytes(true, false, 0x1, b"two", None);
        bytes.extend_from_slice(&second);
        let (first, used) = next_frame(&bytes).expect("a frame").expect("there");
        assert_eq!(first.payload, b"one".to_vec());
        let (next, used2) = next_frame(&bytes[used..]).expect("a frame").expect("there too");
        assert_eq!(next.payload, b"two".to_vec());
        assert_eq!(used + used2, bytes.len(), "between them they used all of it");
    }

    /// The three length forms, and the opcodes, in one pass.
    #[test]
    fn lengths_and_opcodes_matrix() {
        use crate::test_utils::assert_table;
        assert_table!(
            [
                ("7-bit length", 5usize),
                ("the largest 7-bit length", 125),
                ("16-bit length at its smallest", 126),
                ("16-bit length", 4096),
                ("64-bit length", 70_000),
            ],
            |idx, (what, len)| {
                let payload = vec![0xABu8; len];
                let bytes = frame_bytes(true, false, 0x2, &payload, Some([1, 2, 3, 4]));
                let (frame, used) = next_frame(&bytes).expect("a frame").unwrap_or_else(|| panic!("case #{idx} ({what})"));
                assert_eq!(frame.payload, payload, "case #{idx} ({what})");
                assert_eq!(used, bytes.len(), "case #{idx} ({what})");
            }
        );

        assert_table!(
            [
                (0x0u8, Opcode::Continuation, false),
                (0x1, Opcode::Text, false),
                (0x2, Opcode::Binary, false),
                (0x8, Opcode::Close, true),
                (0x9, Opcode::Ping, true),
                (0xA, Opcode::Pong, true),
                (0x3, Opcode::Reserved(0x3), false),
                (0xB, Opcode::Reserved(0xB), true),
            ],
            |idx, (bits, want, control)| {
                let bytes = frame_bytes(true, false, bits, b"x", None);
                let (frame, _) = next_frame(&bytes).expect("a frame").expect("there");
                assert_eq!(frame.opcode, want, "case #{idx}");
                assert_eq!(frame.opcode.is_control(), control, "case #{idx}: control frame?");
            }
        );
    }

    /// RSV1 on the first frame of a message is how the compression extension says the payload
    /// is deflated, so it has to survive parsing.
    #[test]
    fn the_compression_bit_is_kept() {
        let bytes = frame_bytes(true, true, 0x1, b"...", None);
        let (frame, _) = next_frame(&bytes).expect("a frame").expect("there");
        assert!(frame.rsv1, "a reader has to know the payload was compressed");
    }

    /// A length nothing could sensibly hold is refused rather than allocated for.
    #[test]
    fn an_absurd_length_is_refused_rather_than_allocated() {
        let mut bytes = vec![0x82, 127];
        bytes.extend_from_slice(&(u64::MAX / 2).to_be_bytes());
        assert_eq!(next_frame(&bytes), Err(FrameError::TooLarge(u64::MAX / 2)));
    }
}
