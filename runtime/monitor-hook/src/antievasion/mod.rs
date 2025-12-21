use crate::config::AntiEvasionConfig;
use anyhow::Result;

pub mod cpu;
pub mod filesystem;
pub mod firmware;
pub mod hardware;
pub mod human;
pub mod network;
pub mod os_features;
pub mod os_objects;
pub mod os_queries;
pub mod processes;
pub mod registry;
pub mod timing;
pub mod ui;

pub fn install(config: &AntiEvasionConfig) -> Result<()> {
    if config.timing.enabled {
        unsafe {
            timing::install(&config.timing)?;
        }
    }

    if config.filesystem.enabled {
        unsafe {
            filesystem::install(&config.filesystem)?;
        }
    }

    if config.registry.enabled {
        unsafe {
            registry::install(&config.registry)?;
        }
    }

    if config.os_queries.enabled {
        unsafe {
            os_queries::install(&config.os_queries)?;
        }
    }

    if config.os_objects.enabled {
        unsafe {
            os_objects::install(&config.os_objects)?;
        }
    }

    if config.ui.enabled {
        unsafe {
            ui::install(&config.ui)?;
        }
    }

    if config.os_features.enabled {
        unsafe {
            os_features::install(&config.os_features)?;
        }
    }

    if config.processes.enabled {
        unsafe {
            processes::install(&config.processes)?;
        }
    }

    if config.network.enabled {
        unsafe {
            network::install(&config.network)?;
        }
    }

    if config.cpu.enabled {
        unsafe {
            cpu::install(&config.cpu)?;
        }
    }

    if config.hardware.enabled {
        unsafe {
            hardware::install(&config.hardware)?;
        }
    }

    if config.firmware.enabled {
        unsafe {
            firmware::install(&config.firmware)?;
        }
    }

    if config.human.enabled {
        unsafe {
            human::install(&config.human)?;
        }
    }

    crate::pipe::send_status("antievasion_installed", None);
    Ok(())
}
