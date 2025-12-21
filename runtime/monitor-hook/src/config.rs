use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HookConfig {
    #[serde(default)]
    pub categories: Vec<String>,

    #[serde(default)]
    pub specific_hooks: Vec<String>,

    #[serde(default)]
    pub generic_hooks: Vec<GenericHook>,

    #[serde(default)]
    pub anti_evasion: AntiEvasionConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GenericHook {
    pub dll: String,
    pub function: String,
    pub num_args: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AntiEvasionConfig {
    #[serde(default)]
    pub timing: TimingConfig,
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    #[serde(default)]
    pub registry: RegistryConfig,
    #[serde(default)]
    pub os_queries: OsQueriesConfig,
    #[serde(default)]
    pub os_objects: OsObjectsConfig,
    #[serde(default)]
    pub ui: UiConfig,
    #[serde(default)]
    pub os_features: OsFeaturesConfig,
    #[serde(default)]
    pub processes: ProcessesConfig,
    #[serde(default)]
    pub network: NetworkConfig,
    #[serde(default)]
    pub cpu: CpuConfig,
    #[serde(default)]
    pub hardware: HardwareConfig,
    #[serde(default)]
    pub firmware: FirmwareConfig,

    #[serde(default)]
    pub human: HumanConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TimingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub sleep_skip_enabled: bool,
    #[serde(default = "default_sleep_threshold")]
    pub sleep_skip_threshold_ms: u64,
    #[serde(default = "default_one")]
    pub time_acceleration_factor: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct FilesystemConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub hide_vm_files: bool,
    #[serde(default)]
    pub hide_analysis_tools: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct RegistryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub hide_vm_keys: bool,
    #[serde(default)]
    pub spoof_hardware_ids: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OsQueriesConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub spoof_username: Option<String>,
    #[serde(default)]
    pub spoof_computername: Option<String>,
    #[serde(default)]
    pub hide_debugger: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OsObjectsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub hide_vm_devices: bool,
    #[serde(default)]
    pub hide_analysis_mutexes: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct UiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub spoof_screen_resolution: Option<(u32, u32)>,
    #[serde(default)]
    pub spoof_monitor_count: Option<u32>,
    #[serde(default)]
    pub hide_vm_windows: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct OsFeaturesConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub hide_hypervisor: bool,
    #[serde(default)]
    pub spoof_memory_size: Option<u64>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ProcessesConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub hide_analysis_processes: bool,
    #[serde(default)]
    pub hidden_process_names: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct NetworkConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub spoof_mac_address: Option<String>,
    #[serde(default)]
    pub hide_vm_adapters: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CpuConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub hide_hypervisor_bit: bool,
    #[serde(default)]
    pub spoof_core_count: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct HardwareConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub spoof_disk_size: Option<u64>,
    #[serde(default)]
    pub spoof_bios_vendor: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct FirmwareConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub hide_smbios_vm_strings: bool,
    #[serde(default)]
    pub hide_acpi_vm_strings: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct HumanConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mouse_movement: bool,
    #[serde(default)]
    pub keyboard_activity: bool,
    #[serde(default)]
    pub random_delays: bool,
}

fn default_sleep_threshold() -> u64 {
    100
}
fn default_one() -> u64 {
    1
}

impl Default for HookConfig {
    fn default() -> Self {
        Self {
            categories: Vec::new(),
            specific_hooks: Vec::new(),
            generic_hooks: Vec::new(),
            anti_evasion: AntiEvasionConfig::default(),
        }
    }
}
