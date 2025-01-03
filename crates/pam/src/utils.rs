use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use serde::Serialize;

// Program mode
#[derive(Clone, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
  // Issue mode (Issue the challenge)
  Issue,

  // Verify mode (Verify the challenge)
  Verify,

  // Combined mode (Issue + Verify)
  Combined,
}

/// Simple program to greet a person
#[derive(Debug, Parser)]
#[command(
  name = "libpam_oauth",
  display_name = "PAM OAuth PAM module",
  about = "This is the PAM module for the PAM OAuth system",
  version,
  author
)]
pub struct Args {
  /// Config file pat
  #[arg(long)]
  pub config: PathBuf,

  /// Program mode
  #[arg(long)]
  pub mode: Mode,
}
