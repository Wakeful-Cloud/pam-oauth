extern crate pam;

mod args;

use clap::Parser;
use pam::constants::{PamFlag, PamResultCode, PAM_TEXT_INFO};
use pam::conv::Conv;
use pam::module::{PamHandle, PamHooks};
use pam::pam_try;
use std::ffi::CStr;
use std::thread::sleep;
use std::time::Duration;

const TEST: &str = "xyz";

/// PAM OAuth module
struct PamOAuth;
pam::pam_hooks!(PamOAuth);

impl PamHooks for PamOAuth {
  fn sm_authenticate(pamh: &mut PamHandle, args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
    // Convert the arguments to Rust strings (Prepend a fake arg0 to make clap happy)
    let args: Vec<String> = std::iter::once("pam_oauth".to_string())
      .chain(args.iter().map(|arg| arg.to_string_lossy().into_owned()))
      .collect::<Vec<String>>();

    // Parse the arguments
    let args = match args::App::try_parse_from(args) {
      Ok(args) => args,
      Err(err) => {
        println!("Failed to parse arguments: {}", err);
        return PamResultCode::PAM_SERVICE_ERR;
      }
    };

    // Get the conversation
    let conv = match pam_try!(pamh.get_item::<Conv>()) {
      Some(conv) => conv,
      None => {
        println!("Failed to get conversation");
        return PamResultCode::PAM_CONV_ERR;
      }
    };

    // Run in the appropriate mode
    match args.mode {
      args::Mode::Issue => {
        // Get the username
        let user = pam_try!(pamh.get_user(None));

        // Create a boxed string for the username
        let user_box = Box::new(user.clone());

        // Store the username
        pam_try!(pamh.set_data(TEST, user_box));

        pam_try!(conv.send(
          PAM_TEXT_INFO,
          format!("[Issue mode] Username: {}", user).as_str()
        ));
      }
      args::Mode::Verify => {
        // Get the username
        let user = pam_try!(unsafe { pamh.get_data::<String>(TEST) });

        pam_try!(conv.send(
          PAM_TEXT_INFO,
          format!("[Verify mode] Username: {}", user).as_str()
        ));

        // Wait for 10 seconds
        sleep(Duration::from_secs(10));
      }
      args::Mode::Combined => {}
    }

    PamResultCode::PAM_SUCCESS
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
