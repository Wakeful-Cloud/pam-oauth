extern crate pam;

use pam::constants::{PamFlag, PamResultCode};
use pam::module::{PamHandle, PamHooks};
use pam::pam_try;
use std::ffi::CStr;

/// PAM OAuth module
struct PamOAuth;
pam::pam_hooks!(PamOAuth);

impl PamHooks for PamOAuth {
  fn sm_authenticate(pamh: &mut PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
    // Get username
    let user = pam_try!(pamh.get_user(None));

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
