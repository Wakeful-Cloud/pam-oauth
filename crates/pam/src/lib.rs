extern crate pam;

mod api;
mod utils;

use clap::Parser;
use pam::constants::{PamFlag, PamResultCode, PAM_PROMPT_ECHO_ON};
use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use pam::pam_try;
use std::ffi::CStr;

/// PAM OAuth module
struct PamOAuth;
pam::pam_hooks!(PamOAuth);

impl PamHooks for PamOAuth {
  fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
    // Convert the arguments to Rust strings
    let args = args
      .iter()
      .map(|arg| arg.to_string_lossy().into_owned())
      .collect::<Vec<String>>();

    // Parse the arguments
    let args = match utils::Args::try_parse_from(args) {
      Ok(args) => args,
      Err(err) => {
        println!("Failed to parse arguments: {}", err);
        return PamResultCode::PAM_SERVICE_ERR;
      }
    };

    // Run in the appropriate mode
    match args.mode {
      utils::Mode::Verify => {}
      utils::Mode::Issue => {}
      utils::Mode::Combined => {}
    }

    // Get username
    let user = pam_try!(pamh.get_user(None));

    // Get the conversation
    let conv = match pam_try!(pamh.get_item::<Conv>()) {
      Some(conv) => conv,
      None => {
        println!("Failed to get conversation");
        return PamResultCode::PAM_CONV_ERR;
      }
    };

    let password = match pam_try!(conv.send(PAM_PROMPT_ECHO_ON, "Enter your password: ")) {
      Some(password) => password,
      None => {
        println!("Failed to get password");
        return PamResultCode::PAM_AUTH_ERR;
      }
    };

    PamResultCode::PAM_AUTH_ERR
  }

  fn sm_setcred(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
    PamResultCode::PAM_SUCCESS
  }

  fn acct_mgmt(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
    PamResultCode::PAM_SERVICE_ERR
  }

  fn sm_open_session(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
    PamResultCode::PAM_SERVICE_ERR
  }

  fn sm_close_session(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
    PamResultCode::PAM_SERVICE_ERR
  }

  fn sm_chauthtok(_pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
    PamResultCode::PAM_SERVICE_ERR
  }
}
