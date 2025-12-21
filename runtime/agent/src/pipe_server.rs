use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::mpsc;

const PIPE_NAME: &str = r"\\.\pipe\loonaro-hook";

#[derive(Deserialize, Debug)]
struct InitMessage {
    pid: u32,
    process_name: String,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "event_type")]
pub enum HookEvent {
    #[serde(rename = "status")]
    Status {},

    #[serde(rename = "NtAllocateVirtualMemory")]
    MemoryAlloc {
        base_address: usize,
        region_size: usize,
        protect: u32,
    },

    #[serde(rename = "NtWriteVirtualMemory")]
    MemoryWrite {},

    #[serde(rename = "NtProtectVirtualMemory")]
    MemoryProtect { new_protect: u32 },

    #[serde(rename = "connect")]
    NetworkConnect {},

    #[serde(rename = "send")]
    NetworkSend {},

    #[serde(rename = "recv")]
    NetworkRecv {},

    #[serde(rename = "InternetOpenUrlA")]
    HttpRequest {},

    #[serde(rename = "NtCreateThreadEx")]
    ThreadCreate {},

    #[serde(rename = "NtResumeThread")]
    ThreadResume {},

    #[serde(rename = "NtSetContextThread")]
    ThreadSetContext {},

    #[serde(rename = "BCryptEncrypt")]
    CryptoEncrypt {},

    #[serde(rename = "BCryptDecrypt")]
    CryptoDecrypt {},

    #[serde(rename = "BCryptHashData")]
    CryptoHash {},

    #[serde(rename = "CryptEncrypt")]
    LegacyCryptoEncrypt {},

    #[serde(rename = "CryptDecrypt")]
    LegacyCryptoDecrypt {},

    #[serde(rename = "Sleep")]
    Sleep {},

    #[serde(rename = "SleepEx")]
    SleepEx {},

    #[serde(rename = "generic_hook")]
    GenericHook {},

    #[serde(other)]
    Unknown,
}

#[derive(Serialize)]
struct HookConfig {
    categories: Vec<String>,
    specific_hooks: Vec<String>,
    generic_hooks: Vec<GenericHookDef>,
    anti_evasion: AntiEvasionConfig,
}

#[derive(Serialize)]
struct GenericHookDef {
    dll: String,
    function: String,
    num_args: usize,
}

#[derive(Serialize)]
struct AntiEvasionConfig {
    sleep_skip_enabled: bool,
    sleep_skip_threshold_ms: u64,
    time_acceleration_factor: u64,
}

pub async fn run_server(tx: mpsc::Sender<(u32, String, HookEvent)>) -> Result<()> {
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(PIPE_NAME)
        .context("Failed to create named pipe server")?;

    println!("[PipeServer] Listening on {}", PIPE_NAME);

    loop {
        server.connect().await.context("Pipe connect failed")?;

        let client = server;
        server = ServerOptions::new()
            .create(PIPE_NAME)
            .context("Failed to create next pipe instance")?;

        let tx_clone = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(client, tx_clone).await {
                eprintln!("[PipeServer] Client error: {}", e);
            }
        });
    }
}

const DEFAULT_SLEEP_SKIP_THRESHOLD_MS: u64 = 100;
const DEFAULT_TIME_ACCELERATION: u64 = 10;

async fn handle_client(
    pipe: NamedPipeServer,
    tx: mpsc::Sender<(u32, String, HookEvent)>,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(pipe);
    let mut buf_reader = BufReader::new(reader);

    let mut line = String::new();
    let n = buf_reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(());
    }

    let init: InitMessage = serde_json::from_str(&line).context("Failed to parse handshake")?;
    println!(
        "[Hook] Connected: {} (PID: {})",
        init.process_name, init.pid
    );

    let config = HookConfig {
        categories: vec!["all".into()],
        specific_hooks: vec![],
        generic_hooks: vec![],
        anti_evasion: AntiEvasionConfig {
            sleep_skip_enabled: true,
            sleep_skip_threshold_ms: DEFAULT_SLEEP_SKIP_THRESHOLD_MS,
            time_acceleration_factor: DEFAULT_TIME_ACCELERATION,
        },
    };

    let config_json = serde_json::to_string(&config)?;
    writer.write_all(config_json.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;

    loop {
        line.clear();
        let n = buf_reader.read_line(&mut line).await?;
        if n == 0 {
            break;
        }

        match serde_json::from_str::<HookEvent>(&line) {
            Ok(event) => {
                if let Err(e) = tx.send((init.pid, init.process_name.clone(), event)).await {
                    eprintln!("Failed to forward hook event: {}", e);
                    break;
                }
            }
            Err(e) => eprintln!(
                "[Hook PID:{}] Parse error: {} - {}",
                init.pid,
                e,
                line.trim()
            ),
        }
    }

    println!("[Hook] Disconnected: PID {}", init.pid);
    Ok(())
}
