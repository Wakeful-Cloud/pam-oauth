use std::{
  collections::HashSet,
  fs::OpenOptions,
  io::{Read, Seek, Write},
};

use clap::Parser;
use nss::patch_nss;
use pam::patch_pam;
use regex::Regex;

mod args;
mod nss;
mod pam;
mod utils;

/// PAM raw search pattern
const PAM_RAW_SEARCH_PATTERN: &str =
  r"^auth\s+\[success=1\s+default=ignore\]\s+pam_unix\.so\s+nullok$";

/// PAM lines to patch with
const PAM_PATCH_LINES: [&str; 2] = [
  "auth    [default=ignore]                pam_oauth.so --mode issue",
  "auth    [success=2 default=ignore]      pam_oauth.so --mode verify",
];

/// NSS databases to search for
const NSS_SEARCH_DATABASES: [&str; 4] = ["passwd", "group", "shadow", "gshadow"];

/// NSS source to patch with
const NSS_PATCH_SOURCE: &str = "oauth";

fn main() {
  // Parse the arguments
  let args = args::App::parse();

  // Match the command
  match args.command {
    args::Commands::Configure {
      pam,
      nss,
      ssh,
      subcommand,
    } => {
      // Open the configuration files
      let mut pam_file = OpenOptions::new()
        .create(false)
        .read(true)
        .write(true)
        .open(&pam)
        .unwrap();
      let mut nss_file = OpenOptions::new()
        .create(false)
        .read(true)
        .write(true)
        .open(&nss)
        .unwrap();
      // let mut ssh_file = OpenOptions::new()
      //   .create(false)
      //   .read(true)
      //   .write(true)
      //   .open(&ssh)
      //   .unwrap();

      // Read the contents
      let mut pam_contents_before = String::new();
      let mut nss_contents_before = String::new();
      // let mut ssh_contents_before = String::new();

      pam_file.read_to_string(&mut pam_contents_before).unwrap();
      nss_file.read_to_string(&mut nss_contents_before).unwrap();
      // ssh_file.read_to_string(&mut ssh_contents_before).unwrap();

      // Patch
      let add = match subcommand {
        args::ConfigureSubcommands::Setup {} => true,
        args::ConfigureSubcommands::Cleanup {} => false,
      };

      let pam_contents_after = patch_pam(
        &pam_contents_before,
        &Regex::new(PAM_RAW_SEARCH_PATTERN).unwrap(),
        &PAM_PATCH_LINES,
        add,
      )
      .unwrap();

      let nss_contents_after = patch_nss(
        &nss_contents_before,
        &HashSet::from(NSS_SEARCH_DATABASES),
        NSS_PATCH_SOURCE,
        add,
      )
      .unwrap();

      // Seek to the beginning and truncate the files
      pam_file.rewind().unwrap();
      nss_file.rewind().unwrap();
      // ssh_file.rewind().unwrap();
      pam_file.set_len(0).unwrap();
      nss_file.set_len(0).unwrap();
      // ssh_file.set_len(0).unwrap();

      // Overwrite the configuration files
      pam_file.write_all(pam_contents_after.as_bytes()).unwrap();
      nss_file.write_all(nss_contents_after.as_bytes()).unwrap();
      // ssh_file.write_all(ssh_contents_after.as_bytes()).unwrap();
    }
  }
}
