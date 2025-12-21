use crate::config::HookConfig;
use anyhow::{Context, Result};
use once_cell::sync::OnceCell;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::sync::Mutex;

const PIPE_PATH: &str = r"\\.\pipe\loonaro-hook";
const MAX_CONNECT_RETRIES: u32 = 10;
const RETRY_DELAY_MS: u64 = 100;

static PIPE_WRITER: OnceCell<Mutex<BufWriter<File>>> = OnceCell::new();

#[derive(Serialize)]
struct InitMessage {
    pid: u32,
    process_name: String,
}

#[derive(Serialize)]
struct StatusMessage {
    event_type: &'static str,
    status: String,
    error: Option<String>,
}

pub fn connect_and_handshake() -> Result<HookConfig> {
    let file = connect_with_retry()?;
    let read_file = file.try_clone().context("Failed to clone pipe handle")?;

    let mut writer = BufWriter::new(file);
    let mut reader = BufReader::new(read_file);

    send_init_message(&mut writer)?;
    let config = receive_config(&mut reader)?;

    PIPE_WRITER
        .set(Mutex::new(writer))
        .map_err(|_| anyhow::anyhow!("Pipe writer already initialized"))?;

    Ok(config)
}

fn connect_with_retry() -> Result<File> {
    for attempt in 1..=MAX_CONNECT_RETRIES {
        match OpenOptions::new().read(true).write(true).open(PIPE_PATH) {
            Ok(file) => return Ok(file),
            Err(_) if attempt < MAX_CONNECT_RETRIES => {
                std::thread::sleep(std::time::Duration::from_millis(RETRY_DELAY_MS));
            }
            Err(e) => return Err(e).context("Failed to connect to agent pipe after retries"),
        }
    }
    unreachable!()
}

fn send_init_message(writer: &mut BufWriter<File>) -> Result<()> {
    let init_msg = InitMessage {
        pid: std::process::id(),
        process_name: std::env::current_exe()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
    };

    let json = serde_json::to_string(&init_msg)?;
    writeln!(writer, "{}", json)?;
    writer.flush()?;
    Ok(())
}

fn receive_config(reader: &mut BufReader<File>) -> Result<HookConfig> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    serde_json::from_str(&line).context("Failed to parse HookConfig from agent")
}

/// Send a status update to the agent (e.g., initialization progress, errors)
pub fn send_status(status: &str, error: Option<&str>) {
    let msg = StatusMessage {
        event_type: "status",
        status: status.to_string(),
        error: error.map(|s| s.to_string()),
    };
    send_event(&msg);
}

/// Send an event back to the agent. Called from hook trampolines.
pub fn send_event<T: Serialize>(event: &T) {
    if let Some(mutex) = PIPE_WRITER.get() {
        if let Ok(mut writer) = mutex.lock() {
            if let Ok(json) = serde_json::to_string(event) {
                let _ = writeln!(writer, "{}", json);
                let _ = writer.flush();
            }
        }
    }
}
