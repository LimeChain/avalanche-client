use avalanche_types::packer::Packer;
use avalanche_types::{message::ip_addr_to_bytes, packer::ip::IP_LEN};
use std::net::IpAddr;
use thiserror::Error;
use x509_certificate::X509Certificate;

use crate::network::peer::staking::{self, SignatureValidationError};

pub struct SignedIp {
    pub unsigned_ip: UnsignedIp,
    pub signature: Vec<u8>,
}

pub struct UnsignedIp {
    pub ip: IpAddr,
    pub port: u16,
    pub timestamp: u64,
}

impl UnsignedIp {
    pub fn new(ip: IpAddr, port: u16, timestamp: u64) -> Self {
        Self {
            ip,
            port,
            timestamp,
        }
    }
}

impl SignedIp {
    pub fn new(unsigned_ip: UnsignedIp, signature: Vec<u8>) -> Self {
        Self {
            unsigned_ip,
            signature,
        }
    }

    pub fn verify(&self, cert: &X509Certificate) -> Result<(), SignedIpVerificationError> {
        let packer = Packer::new(IP_LEN + 8, 0);
        pack_ip_with_timestamp(
            &packer,
            self.unsigned_ip.ip,
            self.unsigned_ip.port,
            self.unsigned_ip.timestamp,
        )?;

        let packed = packer.take_bytes();
        staking::check_signature(cert, packed.as_ref(), self.signature.as_ref())?;
        Ok(())
    }
}

pub fn pack_ip_with_timestamp(
    packer: &Packer,
    ip_addr: IpAddr,
    port: u16,
    timestamp: u64,
) -> avalanche_types::errors::Result<()> {
    packer.pack_bytes(&ip_addr_to_bytes(ip_addr))?;
    packer.pack_u16(port)?;
    packer.pack_u64(timestamp)?;
    Ok(())
}

#[derive(Error, Debug)]
pub enum SignedIpVerificationError {
    #[error("Failed to pack ip address")]
    Packing(#[from] avalanche_types::errors::Error),
    #[error("Signature was not correct")]
    Signature(#[from] SignatureValidationError),
}
