use log::{info, warn};
use tokio::net::TcpStream;
use std::io::{self, Error, ErrorKind, Read};
use std::time::SystemTime;

use super::bytes_to_ip_addr;
use crate::peer::ipaddr::{SignedIp, UnsignedIp};
use avalanche_types::ids::node;
use avalanche_types::proto::p2p;
use avalanche_types::proto::p2p::Version;
use tokio_rustls::client::TlsStream;
use tokio::io::AsyncReadExt;
use x509_certificate::X509Certificate;

/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
pub struct TlsClient {
    pub stream: TlsStream<TcpStream>,
    network_id: u32,
    x509_certificate: Option<X509Certificate>,
    ip: Option<SignedIp>,
    peer_node_id: Option<node::Id>,
    peer_cert: Option<rustls::Certificate>,
}

impl TlsClient {
    pub fn new(
        stream: TlsStream<TcpStream>,
        network_id: u32,
    ) -> Self {
        Self {
            stream,
            network_id,
            x509_certificate: None,
            ip: None,
            peer_node_id: None,
            peer_cert: None,
        }
    }

    pub async fn do_read(&mut self) -> io::Result<Option<()>> {
        let mut length = [0; 4];

        match self.stream.read_exact(&mut length).await {
            Ok(read) => debug_assert_eq!(read, 4),
            Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => return Err(err)
        };

        let length = u32::from_be_bytes(length) as usize;

        let mut message = vec![0; length].into_boxed_slice();

        let read_length = self.stream.read_exact(&mut message).await?;

        debug_assert_eq!(read_length, length);

        self.handle_inbound_message(&message);

        Ok(Some(()))
    }

    pub fn handle_version(&mut self, msg: Version) {
        // TODO: There must be a better(earlier) time to extract the certificate data
        if self.handle_certificate().is_err() {
            warn!("Failed to handle peer certificate");
            return;
        }
        if msg.network_id != self.network_id {
            warn!(
                "Peer network ID {} doesn't match our network ID {}",
                msg.network_id, self.network_id
            );
            return;
        }

        let now_unix = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("unexpected None duration_since")
            .as_secs();
        let time_diff = msg.my_time.abs_diff(now_unix);
        if time_diff > 60 {
            warn!("Peer time is off by {} seconds", time_diff);
            return;
        }

        // Skip version compatibility check for now

        if msg.my_version_time.abs_diff(now_unix) > 60 {
            warn!(
                "Peer version time is off by {} seconds",
                msg.my_version_time.abs_diff(now_unix)
            );
            return;
        }

        // Skip subnet handling for now
        if msg.ip_addr.len() != 16 {
            warn!("Peer IP address is not 16 bytes long");
            return;
        }

        let ip_addr = match bytes_to_ip_addr(&msg.ip_addr) {
            Some(ip_addr) => ip_addr,
            None => {
                warn!("Peer IP address is invalid");
                return;
            }
        };

        self.ip = Some(SignedIp::new(
            UnsignedIp::new(ip_addr, msg.ip_port as u16, msg.my_version_time),
            msg.sig.to_vec(),
        ));
        if let Some(cert) = &self.x509_certificate {
            let ip = SignedIp::new(
                UnsignedIp::new(ip_addr, msg.ip_port as u16, msg.my_version_time),
                msg.sig.to_vec(),
            );

            match ip.verify(cert) {
                Ok(()) => {
                    info!("Peer IP address verified");
                    self.ip = Some(ip)
                }
                Err(e) => {
                    warn!("Peer IP address verification failed: {}", e);
                }
            }
        }

        // TODO: Send peer list message
    }

    fn handle_certificate(&mut self) -> io::Result<()> {
        info!("retrieving peer certificates...");
        let peer_certs = self.stream.get_ref().1.peer_certificates();

        let peer_cert = if let Some(peer_certs) = peer_certs.and_then(|slice| slice.first()) {
            peer_certs
        } else {
            return Err(Error::new(
                ErrorKind::NotConnected,
                "no peer certificate found",
            ));
        };

        // The certificate details are used to establish node identity.
        // See https://docs.avax.network/specs/cryptographic-primitives#tls-certificates.
        // The avalanchego certs are intentionally NOT signed by a legitimate CA.
        let peer_node_id = node::Id::from_cert_der_bytes(&peer_cert.0)?;
        let x509_certificate =
            X509Certificate::from_der(&peer_cert.0).expect("failed to parse certificate");

        info!("peer node ID: {}", peer_node_id);

        self.peer_node_id = Some(peer_node_id);
        self.peer_cert = Some(peer_cert.clone());
        self.x509_certificate = Some(x509_certificate);
        Ok(())
    }

    fn handle_inbound_message(&mut self, message: &[u8]) {
        let p2p_msg: p2p::Message =
            prost::Message::decode(message).expect("failed to decode inbound message");

        match p2p_msg.message.unwrap() {
            p2p::message::Message::Ping(_) => {
                info!("Received Ping message");
            }
            p2p::message::Message::Pong(_) => {
                info!("Received Pong message");
            }
            p2p::message::Message::Version(msg) => {
                info!("Received Version message");
                self.handle_version(msg);
            }
            p2p::message::Message::PeerList(msg) => {
                info!("Received Peer list message");
                for (i, claimed_port) in msg.claimed_ip_ports.iter().enumerate() {
                    info!("Peer {}:", i);
                    info!(
                        "Peer claimed ip: {}",
                        bytes_to_ip_addr(&claimed_port.ip_addr).unwrap()
                    );
                    info!("Peer claimed port: {}", claimed_port.ip_port);
                    info!("Peer claimed timestamp: {}", claimed_port.timestamp);
                    info!(
                        "Peer claimed signature: {}",
                        hex::encode(&claimed_port.signature)
                    );
                    info!("Peer claimed tx id: {}", hex::encode(&claimed_port.tx_id));
                    info!(
                        "Peer claimed x509 certificate: {}",
                        hex::encode(&claimed_port.x509_certificate)
                    );
                }
            }
            p2p::message::Message::CompressedZstd(msg) => {
                info!("Received CompressedZstd message");
                let read: &mut dyn Read = &mut msg.as_ref();
                let decompressed =
                    zstd::stream::decode_all(read).expect("failed to decompress zstd message");
                self.handle_inbound_message(&decompressed);
            }
            p2p::message::Message::CompressedGzip(_) => {
                info!("Received CompressedGzip message");
            }
            _ => {
                warn!("Received Unknown message type: {}", hex::encode(message));
            }
        };
    }
}
