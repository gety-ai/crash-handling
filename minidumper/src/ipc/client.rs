use super::{
    ACKED_USER_MESSAGE, ACKED_USER_RESPONSE, ACKED_USER_RESPONSE_PAYLOAD_SIZE, CRASH, CRASH_ACK,
    Header, PING, PONG, SocketName, Stream, checked_user_kind, decode_acked_user_response,
    encode_acked_user_message, set_stream_read_timeout,
};
use crate::{Error, MessageAck};
use std::{
    collections::HashSet,
    io::{ErrorKind, IoSlice},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

const HEADER_SIZE: usize = std::mem::size_of::<Header>();

/// How long a crash request waits for another caller to finish with the socket.
///
/// It has to be bounded: the crash may have interrupted the very thread that
/// holds the lock, and this mutex is not reentrant. Waiting a little first still
/// lets an ordinary in-flight `send_message` complete, which is the difference
/// between losing a minidump and merely delaying it.
///
/// macOS sends crash contexts over its mach port instead, so it never contends
/// for this lock.
#[cfg(not(target_os = "macos"))]
const CRASH_REQUEST_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// A complete frame sent by the server to the client. Every one of these can
/// show up on the socket at any time, so a waiter has to route them rather than
/// assume the next frame is the one it asked for.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ResponseFrame {
    Ack { request_id: u64, status: MessageAck },
    CrashAck,
    Pong,
}

/// The frame the current caller is blocked on.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ExpectedResponse {
    Ack(u64),
    CrashAck,
    Pong,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RouteOutcome {
    /// The frame belonged to an abandoned request and was discarded.
    Discarded,
    /// The awaited frame arrived, with the status it carried (if any).
    Complete(Option<MessageAck>),
}

/// Incremental receive state for the byte-stream transports (macOS/Windows),
/// mirroring the server's [`RecvState`](super::server). Keeping the progress
/// across calls is what lets a timed-out wait resume on a frame boundary rather
/// than resync blindly. Linux SEQPACKET delivers whole datagrams, so it neither
/// needs nor tolerates a stateful reader.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
enum ResponseRecvState {
    Header {
        bytes: [u8; HEADER_SIZE],
        filled: usize,
    },
    Payload {
        kind: u32,
        buffer: [u8; ACKED_USER_RESPONSE_PAYLOAD_SIZE],
        len: usize,
        filled: usize,
    },
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl ResponseRecvState {
    fn new() -> Self {
        Self::Header {
            bytes: [0; HEADER_SIZE],
            filled: 0,
        }
    }

    fn remaining_mut(&mut self) -> &mut [u8] {
        match self {
            Self::Header { bytes, filled } => &mut bytes[*filled..],
            Self::Payload {
                buffer,
                len,
                filled,
                ..
            } => &mut buffer[*filled..*len],
        }
    }

    /// True while a frame has been partially read, which distinguishes an
    /// orderly shutdown from a peer that died mid-frame.
    fn has_partial_frame(&self) -> bool {
        match self {
            Self::Header { filled, .. } => *filled != 0,
            Self::Payload { .. } => true,
        }
    }

    fn advance(&mut self, read: usize) -> Result<Option<ResponseFrame>, Error> {
        match self {
            Self::Header { bytes, filled } => {
                *filled += read;
                if *filled < HEADER_SIZE {
                    return Ok(None);
                }

                let header = Header::from_bytes(bytes)
                    .ok_or(Error::ProtocolError("received an invalid response header"))?;
                let len = response_payload_size(header)?;

                if len == 0 {
                    *self = Self::new();
                    return decode_response_frame(header.kind, &[]).map(Some);
                }

                *self = Self::Payload {
                    kind: header.kind,
                    buffer: [0; ACKED_USER_RESPONSE_PAYLOAD_SIZE],
                    len,
                    filled: 0,
                };
                Ok(None)
            }
            Self::Payload {
                kind,
                buffer,
                len,
                filled,
            } => {
                *filled += read;
                if *filled < *len {
                    return Ok(None);
                }

                let (kind, payload) = (*kind, buffer[..*len].to_vec());
                *self = Self::new();
                decode_response_frame(kind, &payload).map(Some)
            }
        }
    }
}

/// Every server-to-client frame has a fixed payload size, so an unexpected one
/// is a protocol error rather than something to read and discard.
fn response_payload_size(header: Header) -> Result<usize, Error> {
    let expected = match header.kind {
        CRASH_ACK | PONG => 0,
        ACKED_USER_RESPONSE => ACKED_USER_RESPONSE_PAYLOAD_SIZE,
        _ => return Err(Error::ProtocolError("received an unknown response kind")),
    };

    if header.size as usize != expected {
        return Err(Error::ProtocolError(
            "received a response with an unexpected size",
        ));
    }

    Ok(expected)
}

fn decode_response_frame(kind: u32, payload: &[u8]) -> Result<ResponseFrame, Error> {
    match kind {
        CRASH_ACK => Ok(ResponseFrame::CrashAck),
        PONG => Ok(ResponseFrame::Pong),
        ACKED_USER_RESPONSE => {
            let (request_id, status) = decode_acked_user_response(payload)?;
            Ok(ResponseFrame::Ack { request_id, status })
        }
        _ => Err(Error::ProtocolError("received an unknown response kind")),
    }
}

fn timeout_error() -> Error {
    std::io::Error::new(ErrorKind::TimedOut, "timed out waiting for an IPC response").into()
}

/// Serializes everything that touches the socket, so concurrent callers can
/// neither interleave their frames nor steal each other's responses.
struct ClientIo {
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    recv: ResponseRecvState,
    /// Requests whose caller gave up. Their responses may still be in flight and
    /// must be discarded instead of being mistaken for a protocol violation by
    /// whoever waits next — in practice the `CRASH_ACK` of the minidump request.
    abandoned_ack_ids: HashSet<u64>,
    /// Cleared once the frame boundary is no longer known — either because a
    /// response could not be decoded, or because a frame was only partly
    /// written. Reading or writing on from there can only produce garbage, so
    /// every later call fails instead.
    usable: bool,
}

impl ClientIo {
    fn new() -> Self {
        Self {
            #[cfg(not(any(target_os = "linux", target_os = "android")))]
            recv: ResponseRecvState::new(),
            abandoned_ack_ids: HashSet::new(),
            usable: true,
        }
    }

    fn ensure_usable(&self) -> Result<(), Error> {
        if self.usable {
            Ok(())
        } else {
            Err(Error::ProtocolError("the IPC response stream is unusable"))
        }
    }

    /// Writes one whole frame, giving up on the connection if it cannot.
    ///
    /// A byte-stream write can fail after part of a frame is already out. There
    /// is no way to finish that frame afterwards, so appending the next one
    /// would silently desynchronise the server; the connection is retired
    /// instead. Protocol errors are raised before the socket is touched and
    /// leave it intact.
    fn write_frame(&mut self, socket: &Stream, kind: u32, payload: &[u8]) -> Result<(), Error> {
        self.ensure_usable()?;

        match send_frame(socket, kind, payload) {
            Ok(()) => Ok(()),
            Err(err @ Error::Io(_)) => {
                self.usable = false;
                Err(err)
            }
            Err(err) => Err(err),
        }
    }

    fn route_response(
        &mut self,
        expected: ExpectedResponse,
        response: ResponseFrame,
    ) -> Result<RouteOutcome, Error> {
        match response {
            ResponseFrame::Ack { request_id, status }
                if expected == ExpectedResponse::Ack(request_id) =>
            {
                Ok(RouteOutcome::Complete(Some(status)))
            }
            ResponseFrame::Ack { request_id, .. } if self.abandoned_ack_ids.remove(&request_id) => {
                Ok(RouteOutcome::Discarded)
            }
            ResponseFrame::CrashAck if expected == ExpectedResponse::CrashAck => {
                Ok(RouteOutcome::Complete(None))
            }
            ResponseFrame::Pong if expected == ExpectedResponse::Pong => {
                Ok(RouteOutcome::Complete(None))
            }
            _ => {
                self.usable = false;
                Err(Error::ProtocolError("received an unexpected IPC response"))
            }
        }
    }

    /// Waits for `expected`, discarding responses to abandoned requests along
    /// the way. `timeout` is turned into an absolute deadline so a frame that
    /// dribbles in over several reads cannot extend the wait indefinitely.
    fn wait_for(
        &mut self,
        socket: &Stream,
        expected: ExpectedResponse,
        timeout: Option<Duration>,
    ) -> Result<Option<MessageAck>, Error> {
        let deadline = match timeout {
            Some(timeout) => Some(
                Instant::now()
                    .checked_add(timeout)
                    .ok_or(Error::ProtocolError("the response deadline overflowed"))?,
            ),
            None => None,
        };

        let result = self.wait_for_inner(socket, expected, deadline);

        // The timeout is a property of the socket, so it has to be cleared
        // before another call reuses the connection — most importantly the
        // minidump request, whose `CRASH_ACK` wait must stay unbounded.
        match set_stream_read_timeout(socket, None) {
            Ok(()) => result,
            Err(err) => {
                self.usable = false;
                Err(result.err().unwrap_or_else(|| err.into()))
            }
        }
    }

    fn wait_for_inner(
        &mut self,
        socket: &Stream,
        expected: ExpectedResponse,
        deadline: Option<Instant>,
    ) -> Result<Option<MessageAck>, Error> {
        self.ensure_usable()?;

        loop {
            let remaining = match deadline {
                Some(deadline) => Some(
                    deadline
                        .checked_duration_since(Instant::now())
                        .ok_or_else(timeout_error)?,
                ),
                None => None,
            };
            set_stream_read_timeout(socket, remaining)?;

            let response = match self.recv_next_frame(socket) {
                Ok(response) => response,
                // A timed-out read leaves the partially received frame in the
                // decoder, so retrying picks up exactly where it left off.
                Err(Error::Io(err))
                    if deadline.is_some()
                        && matches!(
                            err.kind(),
                            ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                        ) =>
                {
                    continue;
                }
                Err(err) => {
                    self.usable = false;
                    return Err(err);
                }
            };

            match self.route_response(expected, response)? {
                RouteOutcome::Discarded => {}
                RouteOutcome::Complete(status) => return Ok(status),
            }
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn recv_next_frame(&mut self, socket: &Stream) -> Result<ResponseFrame, Error> {
        loop {
            let partial = self.recv.has_partial_frame();
            let read = socket.recv(self.recv.remaining_mut())?;

            if read == 0 {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    if partial {
                        "the peer closed the connection mid-response"
                    } else {
                        "the peer closed the connection while a response was pending"
                    },
                )
                .into());
            }

            if let Some(response) = self.recv.advance(read)? {
                return Ok(response);
            }
        }
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn recv_next_frame(&mut self, socket: &Stream) -> Result<ResponseFrame, Error> {
        // SEQPACKET delivers one whole datagram per `recv`, so the frame is
        // either complete or malformed; the extra byte makes an oversized
        // datagram observable instead of silently truncating it.
        let mut frame = [0; HEADER_SIZE + ACKED_USER_RESPONSE_PAYLOAD_SIZE + 1];
        let received = socket.recv(&mut frame)?;

        if received == 0 {
            return Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "the peer closed the connection while a response was pending",
            )
            .into());
        }

        if received < HEADER_SIZE {
            return Err(Error::ProtocolError(
                "received an undersized response frame",
            ));
        }

        let header = Header::from_bytes(&frame[..HEADER_SIZE])
            .ok_or(Error::ProtocolError("received an invalid response header"))?;
        if received != HEADER_SIZE + response_payload_size(header)? {
            return Err(Error::ProtocolError("received a malformed response frame"));
        }

        decode_response_frame(header.kind, &frame[HEADER_SIZE..received])
    }
}

/// Client side of the connection, which runs in the process that may (or has)
/// crashed to communicate with an external monitor process.
pub struct Client {
    socket: Stream,
    /// `parking_lot` does not poison, so an unrelated failure elsewhere cannot
    /// turn a lock acquisition on the crash path into a second panic.
    io: parking_lot::Mutex<ClientIo>,
    next_request_id: AtomicU64,
    /// On Macos we need this additional mach port based client to send crash
    /// contexts, as, unfortunately, it's the best (though hopefully not only?)
    /// way to get the real info needed by the minidump writer to write the
    /// minidump
    #[cfg(target_os = "macos")]
    port: crash_context::ipc::Client,
}

impl Client {
    /// Creates a new client with the given name.
    ///
    /// # Errors
    ///
    /// The specified socket name is invalid, or a connection cannot be made
    /// with a server
    pub fn with_name<'scope>(sn: SocketName<'scope>) -> Result<Self, Error> {
        cfg_if::cfg_if! {
            if #[cfg(any(target_os = "linux", target_os = "android"))] {
                let socket_addr = match sn {
                    SocketName::Path(path) => {
                        uds::UnixSocketAddr::from_path(path).map_err(|_err| Error::InvalidName)?
                    }
                    SocketName::Abstract(name) => {
                        uds::UnixSocketAddr::from_abstract(name).map_err(|_err| Error::InvalidName)?
                    }
                };

                let socket = Stream::connect_unix_addr(&socket_addr)?;
            } else if #[cfg(target_os = "windows")] {
                let SocketName::Path(path) = sn;
                let socket = Stream::connect(path)?;
            } else if #[cfg(target_os = "macos")] {
                let SocketName::Path(path) = sn;
                let socket = Stream::connect(path)?;

                // Note that sun_path is limited to 108 characters including null,
                // while a mach port name is limited to 128 including null, so
                // the length is already effectively checked here
                let port_name = std::ffi::CString::new(path.to_str().ok_or(Error::InvalidPortName)?).map_err(|_err| Error::InvalidPortName)?;
                let port = crash_context::ipc::Client::create(&port_name)?;
            } else {
                compile_error!("unimplemented target platform");
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Since we aren't sending crash requests as id 0 like for other
            // platforms, we instead abuse it to send the pid of this process
            // so that the server can pair the port and the socket together.
            // This bare one-byte reply is not a protocol frame, so it has to be
            // read before the response decoder starts owning the socket.
            let id_buf = std::process::id().to_ne_bytes();
            send_frame(&socket, CRASH, &id_buf)?;
            let mut ack = [0u8; 1];
            socket.recv(&mut ack)?;
        }

        Ok(Self {
            socket,
            io: parking_lot::Mutex::new(ClientIo::new()),
            next_request_id: AtomicU64::new(1),
            #[cfg(target_os = "macos")]
            port,
        })
    }

    /// Requests that the server generate a minidump for the specified crash
    /// context. This blocks until the server has finished writing the minidump.
    ///
    /// # Linux
    ///
    /// This uses a [`crash_context::CrashContext`] by reference as the size of
    /// it can be larger than one would want in an alternate stack handler, the
    /// use of a reference allows the context to be stored outside of the stack
    /// and heap to avoid that complication, though you may of course generate
    /// one however you like.
    ///
    /// # Windows
    ///
    /// This uses a [`crash_context::CrashContext`] by reference, as
    /// the crash context internally contains pointers into this process'
    /// memory that need to stay valid for the duration of the mindump creation.
    ///
    /// # Macos
    ///
    /// It is _highly_ recommended that you suspend all threads in the current
    /// process (other than the thread that executes this method) via
    /// [`thread_suspend`](https://developer.apple.com/documentation/kernel/1418833-thread_suspend)
    /// (apologies for the terrible documentation, blame Apple) before calling
    /// this method
    pub fn request_dump(&self, crash_context: &crash_context::CrashContext) -> Result<(), Error> {
        cfg_if::cfg_if! {
            if #[cfg(any(target_os = "linux", target_os = "android"))] {
                let crash_ctx_buffer = crash_context.as_bytes();
            } else if #[cfg(target_os = "windows")] {
                use scroll::Pwrite;
                let mut buf = [0u8; 24];
                let written = buf.pwrite(
                    super::DumpRequest {
                        exception_pointers: crash_context.exception_pointers as _,
                        process_id: crash_context.process_id,
                        thread_id: crash_context.thread_id,
                        exception_code: crash_context.exception_code,
                    },
                    0,
                )?;

                let crash_ctx_buffer = &buf[..written];
            } else if #[cfg(target_os = "macos")] {
                self.port.send_crash_context(
                    crash_context,
                    Some(std::time::Duration::from_secs(2)),
                    Some(std::time::Duration::from_secs(5))
                )?;
                Ok(())
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            // A crash can interrupt the very thread that is holding this lock,
            // and it is not reentrant, so waiting unconditionally would turn the
            // crash into a permanent hang of the crashing process.
            let mut io =
                self.io
                    .try_lock_for(CRASH_REQUEST_LOCK_TIMEOUT)
                    .ok_or(Error::ProtocolError(
                        "the IPC client was still busy when the crash request arrived",
                    ))?;
            io.write_frame(&self.socket, CRASH, crash_ctx_buffer)?;

            // Writing the minidump is unbounded, so this wait must be too; a
            // late acknowledged-message response is discarded rather than
            // mistaken for the crash ack.
            io.wait_for(&self.socket, ExpectedResponse::CrashAck, None)?;
            Ok(())
        }
    }

    /// Sends a message to the server.
    ///
    /// This method is provided so that users can send their own application
    /// specific messages to the monitor process.
    ///
    /// There are no limits imposed by this method itself, but it is recommended
    /// to keep the message reasonably sized, eg. below 64KiB, as different
    /// targets will have different limits for the maximum payload that can be
    /// delivered.
    ///
    /// Note that this only guarantees the message reached the socket, not that
    /// the server did anything with it. Use [`Self::send_message_acked`] when
    /// the answer matters.
    ///
    /// It is also important to note that this method can be called from multiple
    /// threads if you so choose. Complete delivery of each message is guaranteed
    /// by an internal write loop, and whole frames are serialized so concurrent
    /// senders cannot interleave, but if you care about ordering you will need
    /// to handle that yourself.
    ///
    /// # Errors
    ///
    /// The send to the server fails, or `kind` is in the reserved range
    #[inline]
    pub fn send_message(&self, kind: u32, buf: impl AsRef<[u8]>) -> Result<(), Error> {
        let wire_kind = checked_user_kind(kind)?;

        let mut io = self.io.lock();
        io.write_frame(&self.socket, wire_kind, buf.as_ref())
    }

    /// Sends a message to the server and waits for the handler's verdict on it.
    ///
    /// Unlike [`Self::send_message`], an [`MessageAck::Accepted`] answer is a
    /// statement by the server handler that it has taken ownership of the
    /// message. Any other outcome — including a timeout — means the caller must
    /// assume the server did not.
    ///
    /// # Errors
    ///
    /// The send fails, no response arrives within `timeout`, or `kind` is in the
    /// reserved range
    pub fn send_message_acked(
        &self,
        kind: u32,
        buf: impl AsRef<[u8]>,
        timeout: Duration,
    ) -> Result<MessageAck, Error> {
        checked_user_kind(kind)?;

        let mut io = self.io.lock();
        io.ensure_usable()?;

        // Allocated under the lock so request ids and wire order agree.
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let payload = encode_acked_user_message(request_id, kind, buf.as_ref());

        let result = match io.write_frame(&self.socket, ACKED_USER_MESSAGE, &payload) {
            Ok(()) => io
                .wait_for(
                    &self.socket,
                    ExpectedResponse::Ack(request_id),
                    Some(timeout),
                )
                .and_then(|status| {
                    status.ok_or(Error::ProtocolError(
                        "acknowledged user message returned no status",
                    ))
                }),
            Err(err) => Err(err),
        };

        if result.is_err() {
            io.abandoned_ack_ids.insert(request_id);
        }

        result
    }

    /// Sends a ping to the server, to keep it from reaping connections that haven't
    /// sent a message within its keep alive window
    ///
    /// # Errors
    ///
    /// The send to the server fails
    #[inline]
    pub fn ping(&self) -> Result<(), Error> {
        let mut io = self.io.lock();
        io.write_frame(&self.socket, PING, &[])?;
        io.wait_for(&self.socket, ExpectedResponse::Pong, None)?;
        Ok(())
    }
}

fn send_frame(socket: &Stream, kind: u32, buf: &[u8]) -> Result<(), Error> {
    let size = u32::try_from(buf.len())
        .map_err(|_err| Error::ProtocolError("the payload is too large"))?;
    let header = Header { kind, size };

    let header_bytes = header.as_bytes();
    let mut header_offset = 0;
    let mut payload_offset = 0;

    // Client sockets are blocking, so this loop will not busy-spin. On Linux
    // SEQPACKET a send is atomic (all-or-`EMSGSIZE`), so a message is never
    // split across datagrams and the loop completes in a single iteration.
    // On the macOS/Windows byte streams a short write is possible, so we
    // resend the not-yet-written remainder until the whole frame is out.
    while header_offset < header_bytes.len() || payload_offset < buf.len() {
        let io_bufs = [
            IoSlice::new(&header_bytes[header_offset..]),
            IoSlice::new(&buf[payload_offset..]),
        ];

        let written = match socket.send_vectored(&io_bufs) {
            Ok(written) => written,
            // A signal is not a framing failure, and giving up here would retire
            // a connection that is still perfectly good.
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(err.into()),
        };

        if written == 0 {
            return Err(std::io::Error::new(
                ErrorKind::WriteZero,
                "IPC socket write made no progress",
            )
            .into());
        }

        advance_send_offsets(
            written,
            header_bytes.len(),
            &mut header_offset,
            &mut payload_offset,
        );
    }

    Ok(())
}

/// Advances the header and payload write offsets by `written` bytes, filling the
/// header before the payload to mirror how the two vectored buffers drain.
fn advance_send_offsets(
    written: usize,
    header_len: usize,
    header_offset: &mut usize,
    payload_offset: &mut usize,
) {
    let header_remaining = header_len.saturating_sub(*header_offset);
    let header_written = written.min(header_remaining);
    *header_offset += header_written;
    *payload_offset += written - header_written;
}

#[cfg(test)]
mod tests {
    use super::{ClientIo, ExpectedResponse, ResponseFrame, RouteOutcome, advance_send_offsets};
    use crate::MessageAck;

    #[test]
    fn advances_across_header_and_payload_boundary() {
        let (mut header, mut payload) = (0, 0);
        advance_send_offsets(10, 8, &mut header, &mut payload);
        assert_eq!((header, payload), (8, 2));
    }

    #[test]
    fn advances_only_the_header_while_still_filling_it() {
        let (mut header, mut payload) = (3, 0);
        advance_send_offsets(2, 8, &mut header, &mut payload);
        assert_eq!((header, payload), (5, 0));
    }

    #[test]
    fn advances_from_mid_header_into_payload() {
        let (mut header, mut payload) = (6, 0);
        advance_send_offsets(5, 8, &mut header, &mut payload);
        assert_eq!((header, payload), (8, 3));
    }

    #[test]
    fn advances_only_the_payload_once_header_is_full() {
        let (mut header, mut payload) = (8, 4);
        advance_send_offsets(6, 8, &mut header, &mut payload);
        assert_eq!((header, payload), (8, 10));
    }

    /// The failure this whole protocol exists to prevent: a response to a
    /// request the caller already gave up on must not be mistaken for the crash
    /// ack that the minidump request is waiting for.
    #[test]
    fn late_response_is_discarded_before_the_crash_ack() {
        let mut io = ClientIo::new();
        io.abandoned_ack_ids.insert(23);

        assert_eq!(
            io.route_response(
                ExpectedResponse::CrashAck,
                ResponseFrame::Ack {
                    request_id: 23,
                    status: MessageAck::Accepted,
                },
            )
            .unwrap(),
            RouteOutcome::Discarded
        );
        assert_eq!(
            io.route_response(ExpectedResponse::CrashAck, ResponseFrame::CrashAck)
                .unwrap(),
            RouteOutcome::Complete(None)
        );
        assert!(io.usable);
        assert!(io.abandoned_ack_ids.is_empty());
    }

    #[test]
    fn response_for_an_unknown_request_is_a_protocol_error() {
        let mut io = ClientIo::new();

        assert!(
            io.route_response(
                ExpectedResponse::Ack(1),
                ResponseFrame::Ack {
                    request_id: 2,
                    status: MessageAck::Accepted,
                },
            )
            .is_err()
        );
        assert!(!io.usable);
    }

    #[test]
    fn an_unexpected_response_makes_the_stream_unusable() {
        let mut io = ClientIo::new();

        assert!(
            io.route_response(ExpectedResponse::Pong, ResponseFrame::CrashAck)
                .is_err()
        );
        assert!(!io.usable);
        assert!(io.ensure_usable().is_err());
    }

    /// A byte-stream peer may split a frame anywhere, so the decoder has to
    /// survive being fed one byte at a time and keep its progress in between.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    mod byte_stream {
        use super::super::{HEADER_SIZE, Header, ResponseFrame, ResponseRecvState};
        use crate::MessageAck;

        fn ack_frame(request_id: u64, status: MessageAck) -> Vec<u8> {
            let payload = crate::ipc::encode_acked_user_response(request_id, status);
            let header = Header {
                kind: crate::ipc::ACKED_USER_RESPONSE,
                size: payload.len() as u32,
            };

            let mut frame = Vec::with_capacity(HEADER_SIZE + payload.len());
            frame.extend_from_slice(header.as_bytes());
            frame.extend_from_slice(&payload);
            frame
        }

        /// Feeds `bytes` through the decoder `chunk` bytes at a time, returning
        /// every frame it completed.
        fn feed(
            state: &mut ResponseRecvState,
            bytes: &[u8],
            chunk: usize,
        ) -> Result<Vec<ResponseFrame>, crate::Error> {
            let mut offset = 0;
            let mut frames = Vec::new();

            while offset < bytes.len() {
                let take = chunk
                    .min(bytes.len() - offset)
                    .min(state.remaining_mut().len());
                state.remaining_mut()[..take].copy_from_slice(&bytes[offset..offset + take]);
                offset += take;

                if let Some(frame) = state.advance(take)? {
                    frames.push(frame);
                }
            }

            Ok(frames)
        }

        #[test]
        fn decodes_a_frame_delivered_one_byte_at_a_time() {
            let mut state = ResponseRecvState::new();

            assert_eq!(
                feed(&mut state, &ack_frame(17, MessageAck::Accepted), 1).unwrap(),
                vec![ResponseFrame::Ack {
                    request_id: 17,
                    status: MessageAck::Accepted,
                }]
            );
        }

        #[test]
        fn keeps_partial_progress_so_a_timed_out_wait_can_resume() {
            let frame = ack_frame(18, MessageAck::Rejected);
            let mut state = ResponseRecvState::new();

            // A wait that times out here leaves three header bytes buffered.
            assert!(feed(&mut state, &frame[..3], 1).unwrap().is_empty());
            assert!(state.has_partial_frame());

            assert_eq!(
                feed(&mut state, &frame[3..], 1).unwrap(),
                vec![ResponseFrame::Ack {
                    request_id: 18,
                    status: MessageAck::Rejected,
                }]
            );
        }

        #[test]
        fn rejects_a_response_whose_size_does_not_match_its_kind() {
            let header = Header {
                kind: crate::ipc::ACKED_USER_RESPONSE,
                size: 1,
            };
            let mut state = ResponseRecvState::new();

            assert!(feed(&mut state, header.as_bytes(), 1).is_err());
        }

        #[test]
        fn rejects_an_unknown_response_kind() {
            let header = Header { kind: 99, size: 0 };
            let mut state = ResponseRecvState::new();

            assert!(feed(&mut state, header.as_bytes(), 1).is_err());
        }
    }
}
