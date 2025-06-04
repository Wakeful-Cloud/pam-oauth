use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// App arguments
#[derive(Debug, Parser)]
#[command(
  name = "pam-oauth-client-utils",
  display_name = "PAM OAuth client utilties",
  about = "Utilities for configuring the PAM OAuth client",
  version,
  author
)]
pub struct App {
  /// Command
  #[clap(subcommand)]
  pub command: Commands,
}

/// Commands
#[derive(Debug, Subcommand)]
pub enum Commands {
  /// Configure subcommand
  Configure {
    /// Path to the PAM authentication configuration file to configure
    #[arg(long, default_value = "/etc/pam.d/common-auth")]
    pam: PathBuf,

    /// Path to the NSS configuration file to configure
    #[arg(long, default_value = "/etc/nsswitch.conf")]
    nss: PathBuf,

    /// Path to the SSH configuration file to configure
    #[arg(long, default_value = "/etc/ssh/sshd_config")]
    ssh: PathBuf,

    /// Subcommand
    #[clap(subcommand)]
    subcommand: ConfigureSubcommands,
  },
}

/// Configure subcommands
#[derive(Debug, Subcommand)]
pub enum ConfigureSubcommands {
  /// Setup everything
  Setup {},

  /// Cleanup everything
  Cleanup {},
}
