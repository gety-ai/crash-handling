//! Loopback coverage for acknowledged user messages: a client only learns that
//! the server took ownership of a message by asking for, and receiving, the
//! handler's verdict.

use std::{
    sync::{Arc, atomic},
    time::Duration,
};

type Messages = Arc<parking_lot::Mutex<Vec<(u32, Vec<u8>)>>>;

/// A handler that opts into acknowledged messages and answers with a canned
/// status, optionally after a delay long enough to outlast a client's timeout.
struct AckHandler {
    status: minidumper::MessageAck,
    delay: Duration,
    messages: Messages,
}

impl minidumper::ServerHandler for AckHandler {
    fn create_minidump_file(&self) -> Result<(std::fs::File, std::path::PathBuf), std::io::Error> {
        panic!("should not be called");
    }

    fn on_minidump_created(
        &self,
        _result: Result<minidumper::MinidumpBinary, minidumper::Error>,
    ) -> minidumper::LoopAction {
        panic!("should not be called");
    }

    fn on_message(&self, kind: u32, buffer: Vec<u8>) {
        self.messages.lock().push((kind, buffer));
    }

    fn on_acknowledged_message(&self, kind: u32, buffer: Vec<u8>) -> minidumper::MessageAck {
        std::thread::sleep(self.delay);
        self.messages.lock().push((kind, buffer));
        self.status
    }
}

/// A handler written before acknowledged messages existed, so it only overrides
/// `on_message`.
struct LegacyHandler {
    messages: Messages,
}

impl minidumper::ServerHandler for LegacyHandler {
    fn create_minidump_file(&self) -> Result<(std::fs::File, std::path::PathBuf), std::io::Error> {
        panic!("should not be called");
    }

    fn on_minidump_created(
        &self,
        _result: Result<minidumper::MinidumpBinary, minidumper::Error>,
    ) -> minidumper::LoopAction {
        panic!("should not be called");
    }

    fn on_message(&self, kind: u32, buffer: Vec<u8>) {
        self.messages.lock().push((kind, buffer));
    }
}

struct TestServer {
    name: String,
    shutdown: Arc<atomic::AtomicBool>,
    server_loop: Option<std::thread::JoinHandle<Result<(), minidumper::Error>>>,
}

impl TestServer {
    fn start(test: &str, handler: impl minidumper::ServerHandler + 'static) -> Self {
        let name = format!("minidumper-{test}-{}", uuid::Uuid::new_v4().as_simple());
        let mut server =
            minidumper::Server::with_name(minidumper::SocketName::path(&name)).unwrap();

        let shutdown = Arc::new(atomic::AtomicBool::new(false));
        let is_shutdown = shutdown.clone();
        let server_loop =
            std::thread::spawn(move || server.run(Box::new(handler), &is_shutdown, None));

        Self {
            name,
            shutdown,
            server_loop: Some(server_loop),
        }
    }

    fn connect(&self) -> minidumper::Client {
        minidumper::Client::with_name(minidumper::SocketName::path(&self.name)).unwrap()
    }

    /// Stops the loop and closes every client connection with it.
    fn stop(&mut self) {
        self.shutdown.store(true, atomic::Ordering::Relaxed);
        if let Some(server_loop) = self.server_loop.take() {
            server_loop.join().unwrap().unwrap();
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[test]
fn acknowledged_message_returns_the_handler_verdict() {
    for status in [
        minidumper::MessageAck::Accepted,
        minidumper::MessageAck::Rejected,
    ] {
        let messages = Messages::default();
        let mut server = TestServer::start(
            "verdict",
            AckHandler {
                status,
                delay: Duration::ZERO,
                messages: messages.clone(),
            },
        );
        let client = server.connect();

        assert_eq!(
            client
                .send_message_acked(42, b"payload", Duration::from_secs(5))
                .unwrap(),
            status
        );

        drop(client);
        server.stop();
        assert_eq!(&*messages.lock(), &[(42, b"payload".to_vec())]);
    }
}

/// A handler that does not know about acknowledged messages must still receive
/// the message, and must never be reported as having accepted it.
#[test]
fn legacy_handler_receives_the_message_and_answers_unsupported() {
    let messages = Messages::default();
    let mut server = TestServer::start(
        "unsupported",
        LegacyHandler {
            messages: messages.clone(),
        },
    );
    let client = server.connect();

    assert_eq!(
        client
            .send_message_acked(7, b"legacy", Duration::from_secs(5))
            .unwrap(),
        minidumper::MessageAck::Unsupported
    );

    drop(client);
    server.stop();
    assert_eq!(&*messages.lock(), &[(7, b"legacy".to_vec())]);
}

/// Panic metadata carries a full backtrace, so the payload has to survive being
/// split across many reads.
#[test]
fn acknowledged_message_preserves_a_large_payload() {
    let messages = Messages::default();
    let mut server = TestServer::start(
        "large",
        AckHandler {
            status: minidumper::MessageAck::Accepted,
            delay: Duration::ZERO,
            messages: messages.clone(),
        },
    );
    let client = server.connect();
    let payload = vec![0x5a; 168 * 1024];

    assert_eq!(
        client
            .send_message_acked(8, &payload, Duration::from_secs(10))
            .unwrap(),
        minidumper::MessageAck::Accepted
    );

    drop(client);
    server.stop();
    assert_eq!(&*messages.lock(), &[(8, payload)]);
}

#[test]
fn reserved_kinds_are_rejected_before_reaching_the_wire() {
    let mut server = TestServer::start(
        "reserved",
        LegacyHandler {
            messages: Messages::default(),
        },
    );
    let client = server.connect();

    let reserved = u32::MAX - 4;
    assert!(client.send_message(reserved, b"nope").is_err());
    assert!(
        client
            .send_message_acked(reserved, b"nope", Duration::from_secs(5))
            .is_err()
    );

    drop(client);
    server.stop();
}

#[test]
fn legacy_send_message_and_ping_still_work() {
    let messages = Messages::default();
    let mut server = TestServer::start(
        "legacy-apis",
        AckHandler {
            status: minidumper::MessageAck::Accepted,
            delay: Duration::ZERO,
            messages: messages.clone(),
        },
    );
    let client = server.connect();

    client.send_message(9, b"fire-and-forget").unwrap();
    client.ping().unwrap();

    drop(client);
    server.stop();
    assert_eq!(&*messages.lock(), &[(9, b"fire-and-forget".to_vec())]);
}

/// The scenario the protocol is built around: the caller gives up, the response
/// arrives late anyway, and the next wait on the socket must discard it instead
/// of mistaking it for its own answer.
#[test]
fn a_late_response_is_discarded_by_the_next_wait() {
    let messages = Messages::default();
    let mut server = TestServer::start(
        "late",
        AckHandler {
            status: minidumper::MessageAck::Accepted,
            delay: Duration::from_millis(300),
            messages: messages.clone(),
        },
    );
    let client = server.connect();

    let err = client
        .send_message_acked(10, b"delayed", Duration::from_millis(20))
        .unwrap_err();
    assert!(
        matches!(&err, minidumper::Error::Io(err) if err.kind() == std::io::ErrorKind::TimedOut),
        "expected a timeout, got {err:?}"
    );

    // The handler's late response is drained before this PONG.
    client.ping().unwrap();

    drop(client);
    server.stop();
    assert_eq!(&*messages.lock(), &[(10, b"delayed".to_vec())]);
}

#[test]
fn a_disconnected_server_fails_the_wait_instead_of_hanging() {
    let mut server = TestServer::start(
        "disconnect",
        LegacyHandler {
            messages: Messages::default(),
        },
    );
    let client = server.connect();
    server.stop();

    assert!(
        client
            .send_message_acked(11, b"gone", Duration::from_secs(5))
            .is_err()
    );
}
