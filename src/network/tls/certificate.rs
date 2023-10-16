use random_manager;
use rcgen::CertificateParams;

pub struct Certificate {
    pub key_path: String,
    pub cert_path: String,
}

// Generate x509 certificate and PKSC8 private key
pub fn generate_certificate() -> Result<Certificate, std::io::Error> {
    let client_key_path = random_manager::tmp_path(10, None)?;
    let client_cert_path = random_manager::tmp_path(10, None)?;
    let client_cert_sna_params = CertificateParams::new(vec!["127.0.0.1".to_string()]);
    cert_manager::x509::generate_and_write_pem(
        Some(client_cert_sna_params),
        &client_key_path,
        &client_cert_path,
    )?;

    Ok(Certificate {
        key_path: client_key_path,
        cert_path: client_cert_path,
    })
}