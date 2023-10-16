use crate::crypto::{
    ecdsa,
    error::CryptoError,
    rsa,
};
use thiserror::Error;
use x509_certificate::X509Certificate;

const MAX_CERT_SIZE: usize = 16 * 1024; // 16KiB
pub fn check_signature(
    cert: &X509Certificate,
    msg: &[u8],
    signature: &[u8],
) -> Result<(), SignatureValidationError> {
    validate_certificate(cert)?;

    let alg = cert
        .signature_algorithm()
        .ok_or(SignatureValidationError::UnknownAlgorithm)?;

    match alg {
        x509_certificate::SignatureAlgorithm::RsaSha256 => {
            rsa::verify_pkcs1v15_signature(cert.public_key_data().as_ref(), msg, signature)?;
        }
        x509_certificate::SignatureAlgorithm::EcdsaSha256 => {
            ecdsa::verify_signature(cert.public_key_data().as_ref(), msg, signature)?;
        }
        _ => {
            return Err(SignatureValidationError::Unsupported);
        }
    }
    Ok(())
}

fn validate_certificate(cert: &X509Certificate) -> Result<(), CertificateValidationError> {
    if cert.encode_der().expect("failed to encode").len() > MAX_CERT_SIZE {
        return Err(CertificateValidationError::TooLarge);
    }

    // Skip public key validation for now

    Ok(())
}

#[derive(Error, Debug)]
pub enum SignatureValidationError {
    #[error("Signature failed being verified")]
    Signature(#[from] CryptoError),
    #[error("Could not validate certificate")]
    Certificate(#[from] CertificateValidationError),
    #[error("Unknown signature algorithm")]
    UnknownAlgorithm,
    #[error("Unsupported signature algorithm")]
    Unsupported,
}

#[derive(Error, Debug)]
pub enum CertificateValidationError {
    #[error("Certificate is too large")]
    TooLarge,
    // Add other errors for when validation is fully implemented
}
