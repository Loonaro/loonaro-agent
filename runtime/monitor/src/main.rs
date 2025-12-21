mod artifacts;
mod config;
mod display;
mod pki;
mod processor;
mod telemetry;
mod yara_scan;

use anyhow::{Context, Result};
use comms::Transport;
use std::sync::Arc;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::artifacts::ArtifactCollector;
use crate::config::AppConfig;
use crate::pki::generate_pki;
use crate::processor::collect;
use crate::yara_scan::{ArtifactScanner, YaraScanSummary};

struct TlsServerTransport {
    stream: TlsStream<tokio::net::TcpStream>,
}

impl Transport for TlsServerTransport {
    async fn send(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.stream.write_all(data).await
    }

    async fn receive(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.stream.read(buf).await
    }
}

#[derive(Error, Debug)]
pub enum MonitorError {
    #[error("Failed to parse agent address: {0}")]
    AgentConnectionFailed(#[from] std::net::AddrParseError),

    #[error("Failed to connect to agent: {0}")]
    AgentConnectionError(#[from] tokio::io::Error),

    #[error("TLS Error: {0}")]
    TlsError(#[from] rustls::Error),
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = AppConfig::load();

    // Bind to dynamic port first
    let addr = format!("{}:{}", config.bind_ip, config.bind_port);
    let listener = TcpListener::bind(&addr).await.context("Failed to bind")?;
    let local_addr = listener.local_addr()?;
    let port = local_addr.port();
    let host_ip = "127.0.0.1";

    println!("Monitor listening on {} (Port: {})", local_addr, port);
    println!("Session ID: {}", config.session_id);

    // Report Lifecycle: RUNNING
    telemetry::send_lifecycle(
        &config.moose_url,
        &config.moose_key,
        &config.session_id,
        "RUNNING",
        "Monitor started and waiting for agent.",
    )
    .await;

    // Generate PKI for this session
    let pki = generate_pki(host_ip, port, config.duration).context("Failed to generate PKI")?;

    // Write Config
    let config_dir = std::path::Path::new(&config.output_dir);
    if !config_dir.exists() {
        std::fs::create_dir_all(config_dir)?;
    }
    let config_path = config_dir.join("agent_config.json");
    let config_json = serde_json::to_string_pretty(&pki.agent_config)?;
    std::fs::write(&config_path, config_json)
        .with_context(|| format!("Failed to write agent config to {:?}", config_path))?;
    println!("Wrote agent config to: {:?}", config_path);

    // Configure Server with mTLS (Client Auth Required)
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut pki.agent_config.ca_cert_pem.as_bytes()) {
        roots.add(cert?)?;
    }

    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("Failed to build client verifier")?;

    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(vec![pki.server_cert], pki.server_key)
        .context("Failed to build server config")?;
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    loop {
        let (socket, remote_addr) = listener.accept().await?;
        println!("Accepted connection from: {}", remote_addr);
        let acceptor = acceptor.clone();

        let moose_url = config.moose_url.clone();
        let moose_key = config.moose_key.clone();
        let session_id = config.session_id.clone();
        let output_dir = config.output_dir.clone();

        tokio::spawn(async move {
            match acceptor.accept(socket).await {
                Ok(stream) => {
                    let mut transport = TlsServerTransport { stream };
                    let mut collected_events = Vec::with_capacity(1024);

                    // Initialize artifact collector for this session
                    let mut artifact_collector =
                        ArtifactCollector::new(&session_id, std::path::Path::new(&output_dir));

                    if let Err(e) = collect(
                        &mut transport,
                        &mut collected_events,
                        &moose_url,
                        &moose_key,
                        &session_id,
                        &mut artifact_collector,
                    )
                    .await
                    {
                        eprintln!("Error handling connection from {}: {}", remote_addr, e);
                    }

                    // Session ended - finalize artifacts and run YARA
                    println!("Session {} ended. Finalizing artifacts...", session_id);

                    // Collect final versions of tracked files
                    match artifact_collector.collect_final_versions().await {
                        Ok(files) => println!("Collected {} final file versions", files.len()),
                        Err(e) => eprintln!("Failed to collect final versions: {}", e),
                    }

                    // Save artifact manifest
                    if let Err(e) = artifact_collector.save_manifest().await {
                        eprintln!("Failed to save artifact manifest: {}", e);
                    }

                    // Run YARA scan on collected artifacts
                    let drops_dir = std::path::Path::new(&output_dir).join("drops");
                    if drops_dir.exists() {
                        match ArtifactScanner::new() {
                            Ok(scanner) => {
                                match scanner.scan_directory(&drops_dir) {
                                    Ok(results) => {
                                        let summary = YaraScanSummary::from_results(&results);
                                        println!(
                                            "YARA Scan Complete: {} files, {} matches, severity: {}",
                                            summary.total_files_scanned,
                                            summary.files_with_matches,
                                            summary.severity
                                        );

                                        // Save YARA results
                                        let yara_path = std::path::Path::new(&output_dir)
                                            .join("yara_results.json");
                                        if let Ok(json) = serde_json::to_string_pretty(&summary) {
                                            let _ = tokio::fs::write(&yara_path, json).await;
                                        }
                                    }
                                    Err(e) => eprintln!("YARA scan failed: {}", e),
                                }
                            }
                            Err(e) => eprintln!("Failed to init YARA scanner: {}", e),
                        }
                    }

                    // Log artifact summary
                    let artifact_summary = artifact_collector.summary();
                    println!("Artifact Summary: {:?}", artifact_summary);
                }
                Err(e) => eprintln!("TLS Handshake error from {}: {}", remote_addr, e),
            }
        });
    }
}
