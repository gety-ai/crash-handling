cfg_if::cfg_if! {
    if #[cfg(any(target_os = "linux", target_os = "android"))] {
        use std::os::{
            unix::{prelude::{RawFd, BorrowedFd}, io::AsRawFd},
            fd::AsFd,
        };

        type Stream = uds::UnixSeqpacketConn;

        struct Connection(uds::nonblocking::UnixSeqpacketConn);

        impl polling::AsRawSource for Connection {
            fn raw(&self) -> RawFd {
                self.0.as_raw_fd()
            }
        }

        impl AsRawFd for Connection {
            fn as_raw_fd(&self) -> RawFd {
                self.0.as_raw_fd()
            }
        }

        impl AsFd for Connection {
            fn as_fd(&self) -> BorrowedFd<'_> {
                #[allow(unsafe_code)]
                unsafe { BorrowedFd::borrow_raw(self.as_raw_fd()) }
            }
        }

        impl Connection {
            #[inline]
            fn send(&self, buf: &[u8]) -> Result<usize, std::io::Error> {
                self.0.send(buf)
            }

            #[inline]
            fn recv(&self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
                self.0.recv(buf)
            }

            #[inline]
            fn recv_vectored(&self, buf: &mut [std::io::IoSliceMut<'_>]) -> Result<(usize, bool), std::io::Error> {
                self.0.recv_vectored(buf)
            }
        }

        struct Listener(uds::nonblocking::UnixSeqpacketListener);

        impl polling::AsRawSource for Listener {
            fn raw(&self) -> RawFd {
                self.0.as_raw_fd()
            }
        }

        impl AsRawFd for Listener {
            fn as_raw_fd(&self) -> RawFd {
                self.0.as_raw_fd()
            }
        }

        impl AsFd for Listener {
            fn as_fd(&self) -> BorrowedFd<'_> {
                #[allow(unsafe_code)]
                unsafe { BorrowedFd::borrow_raw(self.as_raw_fd()) }
            }
        }

        impl Listener {
            fn accept_unix_addr(&self) -> Result<(Connection, uds::UnixSocketAddr), std::io::Error> {
                self.0.accept_unix_addr().map(|(conn, addr)| (Connection(conn), addr))
            }
        }
    } else if #[cfg(target_os = "windows")] {
        mod windows;

        type Stream = windows::UnixStream;

        type Listener = windows::UnixListener;
        type Connection = windows::UnixStream;

        // This will of course break if the client and server are built for different
        // arches, but that is the fault of the user in that case
        cfg_if::cfg_if! {
            if #[cfg(target_pointer_width = "32")] {
                type ProtoPointer = u32;
            } else if #[cfg(target_pointer_width = "64")] {
                type ProtoPointer = u64;
            }
        }

        #[derive(scroll::Pwrite, scroll::Pread, scroll::SizeWith)]
        struct DumpRequest {
            /// The address of an `EXCEPTION_POINTERS` in the client's memory
            exception_pointers: ProtoPointer,
            /// The process id of the client process
            process_id: u32,
            /// The id of the thread in the client process in which the crash originated
            thread_id: u32,
            /// The top level exception code, also found in the `EXCEPTION_POINTERS.ExceptionRecord.ExceptionCode`
            exception_code: i32,
        }
    } else if #[cfg(target_os = "macos")] {
        mod mac;

        type Stream = mac::UnixStream;

        type Listener = mac::UnixListener;
        type Connection = mac::UnixStream;

        #[derive(scroll::Pwrite, scroll::Pread, scroll::SizeWith)]
        struct DumpRequest {
            /// The exception code
            code: i64,
            /// Optional subcode, typically only present for `EXC_BAD_ACCESS` exceptions
            subcode: i64,
            /// The process which crashed
            task: u32,
            /// The thread in the process that crashed
            thread: u32,
            /// The thread that handled the exception. This may be useful to ignore.
            handler_thread: u32,
            /// The exception kind
            kind: i32,
            /// Boolean to indicate if there is exception information or not
            has_exception: u8,
            /// Boolean to indicate if there is a subcode
            has_subcode: u8,
        }

    }
}

mod client;
mod server;

pub use client::Client;
pub use server::Server;

const CRASH: u32 = 0;
#[cfg_attr(target_os = "macos", allow(dead_code))]
const CRASH_ACK: u32 = 1;
const PING: u32 = 2;
const PONG: u32 = 3;
const USER: u32 = 4;
/// A user message whose delivery the client wants the handler to confirm.
const ACKED_USER_MESSAGE: u32 = 0xffff_fffe;
/// The server's answer to an [`ACKED_USER_MESSAGE`].
const ACKED_USER_RESPONSE: u32 = 0xffff_ffff;
/// Wire kinds are `USER + kind`, so user kinds must stay below the reserved
/// range or a normal message would be indistinguishable from an acknowledged
/// one on the wire.
const MAX_USER_KIND_EXCLUSIVE: u32 = ACKED_USER_MESSAGE - USER;

/// `request_id: u64` followed by `user_kind: u32`, ahead of the caller's bytes.
const ACKED_USER_MESSAGE_PREFIX_SIZE: usize =
    std::mem::size_of::<u64>() + std::mem::size_of::<u32>();
/// `request_id: u64` followed by the status byte.
const ACKED_USER_RESPONSE_PAYLOAD_SIZE: usize = std::mem::size_of::<u64>() + 1;

/// Translates a user-facing message kind into its wire kind, rejecting the
/// kinds that would collide with the acknowledged-message protocol. This is a
/// runtime check rather than a `debug_assert` because a release build silently
/// forging a protocol frame is far worse than an error return.
fn checked_user_kind(kind: u32) -> Result<u32, crate::Error> {
    if kind >= MAX_USER_KIND_EXCLUSIVE {
        Err(crate::Error::ProtocolError("user message kind is reserved"))
    } else {
        Ok(USER + kind)
    }
}

/// All multi-byte protocol fields use native endianness, matching [`Header`],
/// since both ends of the socket are always the same build.
fn encode_acked_user_message(request_id: u64, user_kind: u32, payload: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(ACKED_USER_MESSAGE_PREFIX_SIZE + payload.len());
    encoded.extend_from_slice(&request_id.to_ne_bytes());
    encoded.extend_from_slice(&user_kind.to_ne_bytes());
    encoded.extend_from_slice(payload);
    encoded
}

fn decode_acked_user_message(mut frame: Vec<u8>) -> Result<(u64, u32, Vec<u8>), crate::Error> {
    if frame.len() < ACKED_USER_MESSAGE_PREFIX_SIZE {
        return Err(crate::Error::ProtocolError(
            "acknowledged user message is too short",
        ));
    }

    let payload = frame.split_off(ACKED_USER_MESSAGE_PREFIX_SIZE);

    let mut request_id = [0; std::mem::size_of::<u64>()];
    request_id.copy_from_slice(&frame[..std::mem::size_of::<u64>()]);
    let mut user_kind = [0; std::mem::size_of::<u32>()];
    user_kind.copy_from_slice(&frame[std::mem::size_of::<u64>()..]);

    Ok((
        u64::from_ne_bytes(request_id),
        u32::from_ne_bytes(user_kind),
        payload,
    ))
}

fn encode_acked_user_response(
    request_id: u64,
    status: crate::MessageAck,
) -> [u8; ACKED_USER_RESPONSE_PAYLOAD_SIZE] {
    let mut payload = [0; ACKED_USER_RESPONSE_PAYLOAD_SIZE];
    payload[..std::mem::size_of::<u64>()].copy_from_slice(&request_id.to_ne_bytes());
    payload[std::mem::size_of::<u64>()] = match status {
        crate::MessageAck::Accepted => 0,
        crate::MessageAck::Rejected => 1,
        crate::MessageAck::Unsupported => 2,
    };
    payload
}

fn decode_acked_user_response(payload: &[u8]) -> Result<(u64, crate::MessageAck), crate::Error> {
    if payload.len() != ACKED_USER_RESPONSE_PAYLOAD_SIZE {
        return Err(crate::Error::ProtocolError(
            "acknowledged user response has an unexpected size",
        ));
    }

    let mut request_id = [0; std::mem::size_of::<u64>()];
    request_id.copy_from_slice(&payload[..std::mem::size_of::<u64>()]);
    let status = match payload[std::mem::size_of::<u64>()] {
        0 => crate::MessageAck::Accepted,
        1 => crate::MessageAck::Rejected,
        2 => crate::MessageAck::Unsupported,
        _ => {
            return Err(crate::Error::ProtocolError(
                "acknowledged user response has an unknown status",
            ));
        }
    };

    Ok((u64::from_ne_bytes(request_id), status))
}

/// Bounds how long a blocking `recv` on the client socket waits, so a response
/// that never arrives cannot wedge the crash path.
///
/// Unix uses `SO_RCVTIMEO` on the raw fd for both socket flavours: `uds` does
/// not expose timeouts on its seqpacket connection, and going through the fd
/// keeps one implementation for Linux and macOS.
fn set_stream_read_timeout(
    stream: &Stream,
    timeout: Option<std::time::Duration>,
) -> std::io::Result<()> {
    cfg_if::cfg_if! {
        if #[cfg(target_os = "windows")] {
            stream.set_read_timeout(timeout)
        } else {
            #[allow(unsafe_code)]
            {
                use std::os::unix::io::AsRawFd as _;

                // An all-zero `timeval` disables the timeout, so a positive but
                // sub-microsecond deadline has to round up to stay a deadline.
                let timeout = timeout.map_or(
                    libc::timeval { tv_sec: 0, tv_usec: 0 },
                    |timeout| {
                        let tv_sec = timeout.as_secs().min(libc::time_t::MAX as u64) as libc::time_t;
                        let tv_usec = timeout.subsec_micros() as libc::suseconds_t;
                        libc::timeval {
                            tv_sec,
                            tv_usec: if tv_sec == 0 && tv_usec == 0 { 1 } else { tv_usec },
                        }
                    },
                );

                // SAFETY: syscall, with a `timeval` of the size `SO_RCVTIMEO` expects
                let res = unsafe {
                    libc::setsockopt(
                        stream.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RCVTIMEO,
                        (&raw const timeout).cast(),
                        std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                    )
                };

                if res == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            }
        }
    }
}

/// A socket name.
///
/// Linux, Windows, and Macos can all use a file path as the name for the socket.
///
/// Additionally, Linux can use a plain string that will be used as an abstract
/// name. See [here](https://man7.org/linux/man-pages/man7/unix.7.html) for
/// more details on abstract namespace sockets.
///
/// Note that on Macos, this name is _also_ used as the name for a mach port.
/// Apple doesn't have good/any documentation for mach port service names, but
/// they are allowed to be longer than the path for a socket name. We also
/// require that the path be utf-8.
#[derive(Copy, Clone)]
pub enum SocketName<'scope> {
    /// The path to the domain socket
    Path(&'scope std::path::Path),
    /// An abstract Linux socket
    #[cfg(any(target_os = "linux", target_os = "android"))]
    Abstract(&'scope str),
}

impl<'scope> SocketName<'scope> {
    /// Create an abstract Linux socket name
    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[inline]
    pub fn abstract_namespace(name: &'scope str) -> Self {
        Self::Abstract(name)
    }

    /// Convenience function to create a [`Self::Path`] from a string
    #[inline]
    pub fn path(path: &'scope str) -> Self {
        Self::Path(std::path::Path::new(path))
    }
}

impl<'scope> From<&'scope std::path::Path> for SocketName<'scope> {
    fn from(s: &'scope std::path::Path) -> Self {
        Self::Path(s)
    }
}

#[derive(Copy, Clone)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
#[repr(C)]
pub struct Header {
    kind: u32,
    size: u32,
}

impl Header {
    fn as_bytes(&self) -> &[u8] {
        #[allow(unsafe_code)]
        unsafe {
            let size = std::mem::size_of::<Self>();
            let ptr = (self as *const Self).cast();
            std::slice::from_raw_parts(ptr, size)
        }
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() != std::mem::size_of::<Self>() {
            return None;
        }

        #[allow(unsafe_code)]
        unsafe {
            Some(std::ptr::read_unaligned(buf.as_ptr().cast::<Self>()))
        }
    }
}

#[cfg(test)]
mod test {
    use super::{
        ACKED_USER_RESPONSE_PAYLOAD_SIZE, Header, MAX_USER_KIND_EXCLUSIVE, USER, checked_user_kind,
        decode_acked_user_message, decode_acked_user_response, encode_acked_user_message,
        encode_acked_user_response,
    };
    use crate::{Error, MessageAck};

    #[test]
    fn header_bytes() {
        let expected = Header {
            kind: 20,
            size: 8 * 1024,
        };
        let exp_bytes = expected.as_bytes();

        let actual = Header::from_bytes(exp_bytes).unwrap();

        assert_eq!(expected, actual);
    }

    #[test]
    fn user_kinds_stop_below_the_reserved_range() {
        assert_eq!(
            checked_user_kind(MAX_USER_KIND_EXCLUSIVE - 1).unwrap(),
            USER + MAX_USER_KIND_EXCLUSIVE - 1
        );
        assert!(matches!(
            checked_user_kind(MAX_USER_KIND_EXCLUSIVE),
            Err(Error::ProtocolError("user message kind is reserved"))
        ));
    }

    #[test]
    fn acked_user_message_roundtrips() {
        let encoded = encode_acked_user_message(0x0102_0304_0506_0708, 42, b"semantic payload");
        let (request_id, user_kind, payload) = decode_acked_user_message(encoded).unwrap();

        assert_eq!(request_id, 0x0102_0304_0506_0708);
        assert_eq!(user_kind, 42);
        assert_eq!(payload, b"semantic payload");
    }

    #[test]
    fn acked_user_message_roundtrips_an_empty_payload() {
        let encoded = encode_acked_user_message(1, 0, &[]);
        assert_eq!(decode_acked_user_message(encoded).unwrap(), (1, 0, vec![]));
    }

    #[test]
    fn acked_user_message_rejects_a_truncated_prefix() {
        assert!(matches!(
            decode_acked_user_message(vec![0; 11]),
            Err(Error::ProtocolError(
                "acknowledged user message is too short"
            ))
        ));
    }

    #[test]
    fn acked_user_response_statuses_roundtrip() {
        for status in [
            MessageAck::Accepted,
            MessageAck::Rejected,
            MessageAck::Unsupported,
        ] {
            let encoded = encode_acked_user_response(99, status);
            assert_eq!(decode_acked_user_response(&encoded).unwrap(), (99, status));
        }
    }

    #[test]
    fn acked_user_response_rejects_a_mis_sized_payload() {
        assert!(decode_acked_user_response(&[0; ACKED_USER_RESPONSE_PAYLOAD_SIZE - 1]).is_err());
        assert!(decode_acked_user_response(&[0; ACKED_USER_RESPONSE_PAYLOAD_SIZE + 1]).is_err());
    }

    #[test]
    fn acked_user_response_rejects_an_unknown_status() {
        let mut encoded = encode_acked_user_response(7, MessageAck::Accepted);
        encoded[std::mem::size_of::<u64>()] = u8::MAX;

        assert!(matches!(
            decode_acked_user_response(&encoded),
            Err(Error::ProtocolError(
                "acknowledged user response has an unknown status"
            ))
        ));
    }
}
