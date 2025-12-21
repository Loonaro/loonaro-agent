use anyhow::Result;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, Ia5String, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::Serialize;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Serialize)]
pub struct AgentConfig {
    pub monitor_ip: String,
    pub monitor_port: u16,
    pub ca_cert_pem: String,
    pub client_cert_pem: String,
    pub client_key_pem: String,
    pub duration_seconds: u64,
}

pub struct Pki {
    pub server_cert: CertificateDer<'static>,
    pub server_key: PrivateKeyDer<'static>,
    pub agent_config: AgentConfig,
}

pub fn generate_pki(monitor_ip: &str, monitor_port: u16, duration: u64) -> Result<Pki> {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Loonaro Root CA");
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_keypair = KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_keypair)?;
    let ca_pem = ca_cert.pem();

    let mut server_params = CertificateParams::default();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "loonaro-monitor");
    server_params.subject_alt_names = vec![
        SanType::DnsName(Ia5String::try_from("loonaro-monitor".to_string())?),
        SanType::IpAddress(IpAddr::from_str(monitor_ip)?),
        SanType::IpAddress(IpAddr::from_str("127.0.0.1")?),
    ];
    server_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    let server_keypair = KeyPair::generate()?;
    let server_cert = server_params.signed_by(&server_keypair, &ca_cert, &ca_keypair)?;
    let server_cert_der = server_cert.der().to_vec();
    let server_key_der = server_keypair.serialize_der();

    let mut client_params = CertificateParams::default();
    client_params
        .distinguished_name
        .push(DnType::CommonName, "loonaro-agent");
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    let client_keypair = KeyPair::generate()?;
    let client_cert = client_params.signed_by(&client_keypair, &ca_cert, &ca_keypair)?;
    let client_pem = client_cert.pem();
    let client_key_pem = client_keypair.serialize_pem();

    Ok(Pki {
        server_cert: CertificateDer::from(server_cert_der),
        server_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_der)),
        agent_config: AgentConfig {
            monitor_ip: monitor_ip.to_string(),
            monitor_port,
            ca_cert_pem: ca_pem,
            client_cert_pem: client_pem,
            client_key_pem: client_key_pem,
            duration_seconds: duration,
        },
    })
}
