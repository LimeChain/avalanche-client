use std::net::IpAddr;

pub mod certificate;
pub mod client;

pub fn bytes_to_ip_addr(bytes: &[u8]) -> Option<IpAddr> {
    let bytes: [u8; 16] = bytes.try_into().ok()?;

    let ip_addr = IpAddr::from(bytes);

    Some(ip_addr)
}
