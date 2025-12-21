use crate::config::{ProtocolConfig, ResponseAction};
use crate::protocol::{ProtocolData, ProtocolEvent, ProtocolService};
use crate::rules::{MatchFields, RuleEngine};
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, server::conn::http1, service::service_fn, Request, Response};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{debug, info};

pub struct HttpService {
    config: ProtocolConfig,
    event_tx: broadcast::Sender<ProtocolEvent>,
    rules: Arc<RuleEngine>,
}

impl HttpService {
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
}

#[async_trait]
impl ProtocolService for HttpService {
    async fn serve(&self) -> Result<()> {
        let addr = SocketAddr::from(([0, 0, 0, 0], self.config.port));
        let listener = TcpListener::bind(addr).await?;
        info!("HTTP service listening on {}", addr);

        let event_tx = Arc::new(self.event_tx.clone());
        let rules = self.rules.clone();

        loop {
            let (stream, remote) = listener.accept().await?;
            let io = TokioIo::new(stream);
            let tx = event_tx.clone();
            let rules = rules.clone();

            tokio::spawn(async move {
                let service = service_fn(move |req| {
                    let tx = tx.clone();
                    let rules = rules.clone();
                    handle_request(req, tx, rules, remote)
                });

                if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                    debug!("HTTP connection error: {}", e);
                }
            });
        }
    }
}

async fn handle_request(
    req: Request<Incoming>,
    event_tx: Arc<broadcast::Sender<ProtocolEvent>>,
    rules: Arc<RuleEngine>,
    remote: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().to_string();
    let uri = req.uri().to_string();
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let content_type = req
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let headers: HashMap<String, String> = req
        .headers()
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|v| (k.to_string(), v.to_string())))
        .collect();

    let body_bytes = req
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();
    let body_preview =
        String::from_utf8_lossy(&body_bytes[..body_bytes.len().min(512)]).to_string();

    debug!("HTTP {} {} from {}", method, uri, remote);

    let fields = MatchFields::http(&method, &uri, host.as_deref(), user_agent.as_deref());

    let (response_body, status, rule_id, tags) = match rules.match_request("http", &fields) {
        Some((
            ResponseAction::HttpResponse {
                status,
                body,
                headers: _,
            },
            id,
            tags,
        )) => (body, status, Some(id), tags),
        Some((ResponseAction::Drop, id, tags)) => {
            let mut event = ProtocolEvent::http(&remote.to_string(), &method, &uri);
            event.matched_rule = Some(id);
            event.tags = tags;
            event.response_summary = Some("DROPPED".into());
            let _ = event_tx.send(event);
            return Ok(Response::builder()
                .status(444) // Connection closed without response
                .body(Full::new(Bytes::new()))
                .unwrap());
        }
        Some((ResponseAction::ServeFile { path }, id, tags)) => {
            let content = tokio::fs::read_to_string(&path).await.unwrap_or_default();
            (content, 200, Some(id), tags)
        }
        _ => {
            let body = generate_default_response(&uri, &method);

            (body, 200, None, Vec::new())
        }
    };

    let event = ProtocolEvent {
        id: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now(),
        protocol: "http".into(),
        source: remote.to_string(),
        event_type: "request".into(),
        data: ProtocolData::Http {
            method: method.clone(),
            uri: uri.clone(),
            host,
            user_agent,
            content_type,
            body_size: body_bytes.len(),
            body_preview: Some(body_preview),
            headers,
        },
        matched_rule: rule_id,
        response_summary: Some(format!("{} ({} bytes)", status, response_body.len())),
        tags,
    };

    let _ = event_tx.send(event);

    Ok(Response::builder()
        .status(status)
        .header("Content-Type", "text/html")
        .header("Server", "Apache/2.4.41")
        .header("X-Powered-By", "PHP/7.4.3")
        .body(Full::new(Bytes::from(response_body)))
        .unwrap())
}

fn generate_default_response(uri: &str, method: &str) -> String {
    if uri.contains(".exe") || uri.contains(".dll") || uri.contains(".bin") {
        "MZ\0\0\0\0\0\0".to_string()
    } else if uri.contains(".php")
        || uri.contains("gate")
        || uri.contains("panel")
        || uri.contains("check")
        || uri.contains("check")
    {
        r#"{"status":"ok","id":"12345","cmd":"sleep","interval":60}"#.to_string()
    } else if uri.contains("update") || uri.contains("config") {
        r#"{"version":"1.0.0","update_url":"http://10.0.0.1/update.exe"}"#.to_string()
    } else if uri.contains(".js") {
        "//".to_string()
    } else if uri.contains(".css") {
        "/**/".to_string()
    } else if uri.contains("api") || method == "POST" {
        r#"{"success":true,"data":{}}"#.to_string()
    } else {
        format!(
            r#"<!DOCTYPE html>
<html>
<head><title>Welcome</title></head>
<body>
<h1>It works!</h1>
<p>Request: {} {}</p>
</body>
</html>"#,
            method, uri
        )
    }
}
