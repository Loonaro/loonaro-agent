use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::PathBuf;
use tokio::process::{Child, Command};
use tokio::time::{sleep, Duration, Instant};
use tracing::{info, warn};

use crate::config::Config;
use crate::providers::{AnalysisContext, AnalysisProvider, Submission};

/// Implementation for Windows Sandbox (Ephemeral)
pub struct WindowsSandboxProvider {
    monitor_bin_path: PathBuf,
    staging_base: PathBuf,
}

impl WindowsSandboxProvider {
    pub fn new(monitor_bin_path: PathBuf, staging_base: PathBuf) -> Self {
        Self {
            monitor_bin_path,
            staging_base,
        }
    }
}

// SandboxHandle wraps the child process in a Mutex so that it can be modified (killed)
// even via a shared or immutable reference to the AnalysisContext.
struct SandboxHandle {
    monitor_process: tokio::sync::Mutex<Child>,
}

#[async_trait]
impl AnalysisProvider for WindowsSandboxProvider {
    fn name(&self) -> &str {
        "Windows Sandbox"
    }

    async fn start_analysis(
        &self,
        submission: &Submission,
        config: &Config,
    ) -> Result<AnalysisContext> {
        let session_id = &submission.job_id;
        let session_dir = self.staging_base.join(session_id);

        if !session_dir.exists() {
            tokio::fs::create_dir_all(&session_dir).await?;
        }

        info!("Spawning Monitor for Session: {}", session_id);

        let mut monitor_cmd = Command::new(&self.monitor_bin_path);
        monitor_cmd
            .arg("--session-id")
            .arg(session_id)
            .arg("--output-dir")
            .arg(&session_dir)
            .arg("--port") // dynamic port
            .arg("--moose-url")
            .arg(&config.moose.host)
            .arg("--moose-key")
            .arg(&config.moose.api_key)
            .arg("--duration")
            .arg(submission.duration_seconds.to_string());

        let mut monitor_child = monitor_cmd
            .spawn()
            .context("Failed to spawn monitor process")?;

        let config_path = session_dir.join("agent_config.json");

        let timeout = Duration::from_secs(15);
        let start = Instant::now();

        info!("Waiting for Monitor to generate keys...");
        loop {
            if config_path.exists() {
                break;
            }
            if start.elapsed() > timeout {
                let _ = monitor_child.kill().await;
                anyhow::bail!("Timed out waiting for Monitor to generate keys.");
            }
            sleep(Duration::from_millis(250)).await;
        }

        let malware_dest = session_dir.join(&submission.file_name);

        tokio::fs::copy(&submission.file_path, &malware_dest)
            .await
            .context("Failed to copy submission to staging")?;

        let bin_dir = self
            .monitor_bin_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Invalid monitor bin path"))?;
        let agent_src = bin_dir.join("agent.exe");
        let agent_dest = session_dir.join("agent.exe");

        if agent_src.exists() {
            tokio::fs::copy(&agent_src, &agent_dest)
                .await
                .context("Failed to copy agent.exe")?;
        } else {
            anyhow::bail!("agent.exe not found at {:?}", agent_src);
        }

        // Create startup script
        let startup_script = format!(
            r#"
$ErrorActionPreference = "Stop"
cd C:\Users\WDAGUtilityAccount\Desktop\loonaro\box_config
Start-Sleep -Seconds 2
./agent.exe
"#
        );
        tokio::fs::write(session_dir.join("sandbox-startup.ps1"), startup_script).await?;

        let wsb_content = format!(
            r#"
<Configuration>
  <VGpu>Enable</VGpu>
  <Networking>Enable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{}</HostFolder>
      <SandboxFolder>C:\Users\WDAGUtilityAccount\Desktop\loonaro\box_config</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>powershell.exe -ExecutionPolicy Bypass -File C:\Users\WDAGUtilityAccount\Desktop\loonaro\box_config\sandbox-startup.ps1</Command>
  </LogonCommand>
</Configuration>
"#,
            session_dir.display()
        );

        let wsb_path = session_dir.join("loonaro.wsb");
        tokio::fs::write(&wsb_path, wsb_content).await?;

        info!("Launching Windows Sandbox...");

        Command::new("WindowsSandbox.exe")
            .arg(&wsb_path)
            .spawn()
            .context("Failed to launch Windows Sandbox")?;

        Ok(AnalysisContext {
            instance_id: session_id.clone(),
            agent_address: "127.0.0.1".to_string(), // Sandbox is local
            handle: Box::new(SandboxHandle {
                monitor_process: tokio::sync::Mutex::new(monitor_child),
            }),
        })
    }

    async fn cleanup(&self, context: &AnalysisContext) -> Result<()> {
        info!("Cleaning up Sandbox session: {}", context.instance_id);

        if let Some(handle) = context.handle.downcast_ref::<SandboxHandle>() {
            let mut child = handle.monitor_process.lock().await;
            if let Err(e) = child.kill().await {
                warn!(
                    "Failed to kill monitor process (may have exited logic): {}",
                    e
                );
            } else {
                info!(
                    "Monitor process terminated for session {}",
                    context.instance_id
                );
            }
        } else {
            warn!(
                "Cleanup failed: Invalid handle type for session {}",
                context.instance_id
            );
        }

        Ok(())
    }
}
