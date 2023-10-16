use crate::bootstrap::Bootstrappers;
use crypto::ecdsa;
use network::peer::ipaddr::pack_ip_with_timestamp;
use avalanche_types::message;
use avalanche_types::packer::ip::IP_LEN;
use avalanche_types::packer::Packer;
use env_logger::Env;
use log::info;
use mio::net::TcpStream;
use network::peer::outbound;
use network::tls::client::TlsClient;
use rustls::ServerName;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, SystemTime};

mod bootstrap;

fn main() {
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "info")
        .write_style_or("MY_LOG_STYLE", "always");

    env_logger::init_from_env(env);

    match start() {
        Ok(_) => info!("Client started"),
        Err(e) => info!("Client failed to start: {}", e),
    }
}

/*
 * Starts the client
 */
fn start() -> io::Result<()> {
    let bootstrappers = Bootstrappers::read_boostrap_json();
    let cert =
        network::tls::certificate::generate_certificate().expect("failed to generate certificate");
    let connector = outbound::Connector::new_from_pem(&cert.key_path, &cert.cert_path)?;

    let peer = bootstrappers.mainnet.get(0).expect("failed to get peer");
    let server_name: ServerName = ServerName::try_from(peer.ip.ip().to_string().as_ref()).unwrap();
    let sock = TcpStream::connect(peer.ip).unwrap();
    let mut tls_client = TlsClient::new(sock, server_name, connector.client_config.clone(), 1);

    let rt = tokio::runtime::Runtime::new().unwrap();

    let now = SystemTime::now();
    let now_unix = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("unexpected None duration_since")
        .as_secs();

    let packer = Packer::new(IP_LEN + 8, 0);
    pack_ip_with_timestamp(&packer, IpAddr::V4(Ipv4Addr::LOCALHOST), 9651, now_unix)
        .expect("failed to pack ip");
    let packed = packer.take_bytes();
    let (private_key, _) = cert_manager::x509::load_pem_key_cert_to_der(
        cert.key_path.as_ref(),
        cert.cert_path.as_ref(),
    )?;

    let signature =
        ecdsa::sign_message(packed.as_ref(), &private_key.0).expect("failed to sign message");

    let sig_bytes: Box<[u8]> = Box::from(signature.as_ref());
    let msg = message::version::Message::default()
        .network_id(1)
        .my_time(now_unix)
        .ip_addr(IpAddr::V4(Ipv4Addr::LOCALHOST))
        .ip_port(9651)
        .my_version("avalanche/1.10.11".to_string())
        .my_version_time(now_unix)
        .sig(sig_bytes.to_vec())
        .tracked_subnets(Vec::new());

    let msg = msg.serialize().expect("failed serialize");
    info!("Sending version message: {}", hex::encode(msg.clone()));

    tls_client.write_message(&msg).expect("failed to write");

    let task = rt.spawn(async move {
        connector
            .connect(tls_client, Duration::from_secs(10))
            .expect("failed to connect to peer");
    });

    rt.block_on(task)?;

    Ok(())
}
