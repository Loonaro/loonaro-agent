use crate::config::{ProtocolConfig, ResponseAction};
use crate::protocol::{ProtocolData, ProtocolEvent, ProtocolService};
use crate::rules::{MatchFields, RuleEngine};
use anyhow::Result;
use async_trait::async_trait;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

pub struct DnsService {
    config: ProtocolConfig,
    event_tx: broadcast::Sender<ProtocolEvent>,
    rules: Arc<RuleEngine>,
}

impl DnsService {
    pub fn new(
        config: ProtocolConfig,
        event_tx: broadcast::Sender<ProtocolEvent>,
        rules: Arc<RuleEngine>,
    ) -> Self {
        Self {
            config,
            event_tx,
            rules,
        }
    }

    fn get_default_ip(&self) -> String {
        self.config
            .options
            .get("default_ip")
            .cloned()
            .unwrap_or_else(|| "10.0.0.1".to_string())
    }
}

#[async_trait]
impl ProtocolService for DnsService {
    async fn serve(&self) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.config.port));
        let socket = UdpSocket::bind(addr).await?;
        info!("DNS service listening on {}", addr);

        let mut buf = [0u8; 512];
        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            if len < 12 {
                continue;
            }

            let query = &buf[..len];
            if let Some((domain, qtype)) = parse_dns_query(query) {
                debug!("DNS query from {}: {} ({})", src, domain, qtype);

                // Check rules
                let fields = MatchFields::dns(&domain);
                let (response_ip, rule_id, tags) = match self.rules.match_request("dns", &fields) {
                    Some((ResponseAction::DnsResolve { ip }, id, tags)) => (ip, Some(id), tags),
                    Some((ResponseAction::Drop, id, tags)) => {
                        let mut event = ProtocolEvent::dns(&src.to_string(), &domain, &qtype);
                        event.matched_rule = Some(id);
                        event.tags = tags;
                        event.response_summary = Some("DROPPED".into());
                        let _ = self.event_tx.send(event);
                        continue;
                    }
                    _ => (self.get_default_ip(), None, Vec::new()),
                };

                let mut event = ProtocolEvent::dns(&src.to_string(), &domain, &qtype);
                if let ProtocolData::Dns {
                    response_ip: ref mut rip,
                    ..
                } = event.data
                {
                    *rip = Some(response_ip.clone());
                }
                event.matched_rule = rule_id;
                event.tags = tags;
                event.response_summary = Some(format!("A {}", response_ip));
                let _ = self.event_tx.send(event);

                if qtype == "A" {
                    if let Some(response) = build_dns_response(query, &response_ip) {
                        if let Err(e) = socket.send_to(&response, src).await {
                            warn!("Failed to send DNS response: {}", e);
                        }
                    }
                }
            }
        }
    }
}

fn parse_dns_query(data: &[u8]) -> Option<(String, String)> {
    if data.len() < 12 {
        return None;
    }

    let mut pos = 12;
    let mut domain_parts = Vec::new();

    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        pos += 1;
        if pos + len > data.len() {
            return None;
        }
        if let Ok(part) = std::str::from_utf8(&data[pos..pos + len]) {
            domain_parts.push(part.to_string());
        }
        pos += len;
    }

    pos += 1;
    if pos + 4 > data.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let qtype_str = match qtype {
        1 => "A",
        28 => "AAAA",
        5 => "CNAME",
        15 => "MX",
        16 => "TXT",
        _ => "OTHER",
    };

    Some((domain_parts.join("."), qtype_str.to_string()))
}

fn build_dns_response(query: &[u8], ip: &str) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }

    let ip_parts: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if ip_parts.len() != 4 {
        return None;
    }

    let mut response = query.to_vec();
    response[2] = 0x85;
    response[3] = 0x80;
    response[6] = 0x00;
    response[7] = 0x01;

    response.extend_from_slice(&[
        0xC0, 0x0C, // Pointer to domain
        0x00, 0x01, // Type A
        0x00, 0x01, // Class IN
        0x00, 0x00, 0x00, 0x3C, // TTL 60s
        0x00, 0x04, // RDATA length
    ]);
    response.extend_from_slice(&ip_parts);

    Some(response)
}
