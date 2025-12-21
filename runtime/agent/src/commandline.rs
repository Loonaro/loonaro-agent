use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Target Monitor IP address to connect to
    #[arg(
        short,
        long,
        default_value = "127.0.0.1",
        help = "Target Monitor IP address to connect to"
    )]
    pub ip: String,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Launch a process and inject the monitor hook
    Run {
        /// Path to the executable to launch
        path: String,

        /// Path to the monitor-hook.dll to inject
        #[arg(
            long,
            default_value = "monitor-hook.dll",
            help = "Path to the monitor-hook.dll to inject"
        )]
        dll: String,
    },
}
