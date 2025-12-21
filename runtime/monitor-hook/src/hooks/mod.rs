use crate::config::HookConfig;
use anyhow::{Context, Result};
use minhook::MinHook;

pub mod crypto;
pub mod generic;
pub mod memory;
pub mod network;
pub mod process;

pub fn install(config: HookConfig) -> Result<()> {
    let enable_all = config.categories.iter().any(|c| c == "all");

    if enable_all
        || config.categories.iter().any(|c| c == "memory")
        || config.specific_hooks.iter().any(|h| h.starts_with("Nt"))
    {
        unsafe {
            memory::install_all().context("Failed to install memory hooks")?;
        }
    }

    if enable_all
        || config.categories.iter().any(|c| c == "network")
        || config
            .specific_hooks
            .iter()
            .any(|h| h.contains("Socket") || h.contains("Internet"))
    {
        unsafe {
            network::install_all().context("Failed to install network hooks")?;
        }
    }

    if enable_all
        || config.categories.iter().any(|c| c == "process")
        || config
            .specific_hooks
            .iter()
            .any(|h| h.contains("Process") || h.contains("Thread"))
    {
        unsafe {
            process::install_all().context("Failed to install process hooks")?;
        }
    }

    if enable_all || config.categories.iter().any(|c| c == "crypto") {
        unsafe {
            crypto::install_all().context("Failed to install crypto hooks")?;
        }
    }

    if !config.generic_hooks.is_empty() {
        unsafe {
            generic::install_hooks(&config.generic_hooks)
                .context("Failed to install generic hooks")?;
        }
    }

    Ok(())
}

pub fn cleanup() -> Result<()> {
    unsafe {
        MinHook::disable_all_hooks().map_err(|e| anyhow::anyhow!("disable_all_hooks: {:?}", e))?;
    }
    Ok(())
}
