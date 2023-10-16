use std::{
    io::{self, Error, ErrorKind, Read, Write},
    sync::Arc,
    time::{Duration, SystemTime},
};

use avalanche_types::ids::node;

use crate::peer::ipaddr::SignedIp;
use crate::tls::client::{TlsClient, CLIENT};
use rustls::Certificate;
use rustls::{ClientConfig, ClientConnection, ServerName};
use x509_certificate::X509Certificate;

/// ref. <https://pkg.go.dev/github.com/ava-labs/avalanchego/network/peer#Start>
pub struct Connector {
    /// The client configuration of the local/source node for outbound TLS connections.
    pub client_config: Arc<ClientConfig>,
    pub network_id: u32,
    pub x509_certificate: Option<X509Certificate>,
    pub ip: Option<SignedIp>,
}

impl Connector {
    /// Creates a new dialer loading the PEM-encoded key and certificate pair of the local node.
    pub fn new_from_pem<S>(key_path: S, cert_path: S) -> io::Result<Self>
    where
        S: AsRef<str>,
    {
        let (private_key, certificate) =
            cert_manager::x509::load_pem_key_cert_to_der(key_path.as_ref(), cert_path.as_ref())?;

        // NOTE: AvalancheGo/* uses TLS key pair for exchanging node IDs without hostname authentication.
        // Thus, ok to skip CA verification, to be consistent with Go tls.Config.InsecureSkipVerify.
        // ref. <https://github.com/ava-labs/avalanchego/blob/master/network/peer/tls_config.go>
        // ref. <https://docs.rs/rustls/latest/rustls/struct.ConfigBuilder.html#method.with_client_auth_cert>
        let config = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification {}))
            .with_client_auth_cert(vec![certificate], private_key)
            .map_err(|e| {
                Error::new(
                    ErrorKind::Other,
                    format!("failed to create TLS client config '{}'", e),
                )
            })?;

        Ok(Self {
            client_config: Arc::new(config),
            network_id: 1,
            x509_certificate: None,
            ip: None,
        })
    }

    /// Creates a connection to the specified peer's IP and port.
    /// ref. <https://pkg.go.dev/github.com/ava-labs/avalanchego/network/peer#NewTLSClientUpgrader>
    pub fn connect(&self, mut tls_client: TlsClient, _timeout: Duration) -> io::Result<Stream> {
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(32);
        poll.registry().register(
            &mut tls_client.socket,
            CLIENT,
            mio::Interest::READABLE | mio::Interest::WRITABLE,
        )?;

        // Start an event loop.
        loop {
            // Poll Mio for events, blocking until we get an event.
            poll.poll(&mut events, None)?;

            // Process each event.
            for event in events.iter() {
                // We can use the token we previously provided to `register` to
                // determine for which socket the event is.
                match event.token() {
                    CLIENT => {
                        tls_client.ready(event);
                        tls_client.reregister(poll.registry())?;
                        break;
                    }
                    // We don't expect any events with tokens other than those we provided.
                    _ => unreachable!(),
                }
            }
        }
    }
}

pub struct NoCertificateVerification {}

impl rustls::client::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> std::result::Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

/// RUST_LOG=debug cargo test --package network --lib -- peer::outbound::test_connector --exact --show-output
#[test]
fn test_connector() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init();

    let key_path = random_manager::tmp_path(10, None).unwrap();
    let cert_path = random_manager::tmp_path(10, None).unwrap();
    cert_manager::x509::generate_and_write_pem(None, &key_path, &cert_path).unwrap();

    let _connector = Connector::new_from_pem(&key_path, &cert_path).unwrap();
}

/// Represents a connection to a peer.
/// ref. <https://github.com/rustls/rustls/commit/b8024301747fb0328c9493d7cf7268e0de17ffb3>
pub struct Stream {
    pub addr: String,

    /// ref. <https://docs.rs/rustls/latest/rustls/enum.Connection.html>
    /// ref. <https://docs.rs/rustls/latest/rustls/client/struct.ClientConnection.html>
    pub conn: ClientConnection,

    pub peer_certificate: Certificate,
    pub peer_node_id: node::Id,

    #[cfg(feature = "pem")]
    pub peer_certificate_pem: String,
}

impl Stream {
    pub fn close(&mut self) -> io::Result<()> {
        self.conn.send_close_notify();
        Ok(())
    }

    /// Writes to the connection.
    pub fn write<S>(&mut self, d: S) -> io::Result<usize>
    where
        S: AsRef<[u8]>,
    {
        let mut wr = self.conn.writer();
        wr.write(d.as_ref())
    }

    /// Reads from the connection.
    pub fn read(&mut self) -> io::Result<Vec<u8>> {
        let mut rd = self.conn.reader();
        let mut d = Vec::new();
        let _ = rd.read_to_end(&mut d)?;
        Ok(d)
    }
}
