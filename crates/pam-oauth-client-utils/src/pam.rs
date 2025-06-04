use regex::Regex;

use crate::utils::{split_lines_with_extensions, PatchError};

/// Patch a PAM file by appending the patch before the search pattern
pub fn patch_pam(
  raw: &str,
  search_pattern: &Regex,
  patch_lines: &[&str],
  add: bool,
) -> Result<String, PatchError> {
  // Split the file into lines (with support for backslash line extensions)
  let mut lines = split_lines_with_extensions(raw);

  // Find the search pattern matching line
  let search_line_index = lines
    .iter()
    .position(|line| search_pattern.is_match(line))
    .ok_or(PatchError::new(&format!(
      "Failed to find search line: {}",
      search_pattern
    )))?;

  // Check if the subsequent lines match the patch lines
  let subsequent_lines_match = search_line_index + 1 + patch_lines.len() <= lines.len()
    && (lines[search_line_index + 1..search_line_index + 1 + patch_lines.len()] == *patch_lines);

  // Patch the lines
  if add {
    // Check that the subsequent lines do not match the patch lines
    if subsequent_lines_match {
      return Err(PatchError::new("Already patched"));
    }

    // Insert the lines
    lines.splice(
      search_line_index + 1..search_line_index + 1,
      patch_lines.iter().map(|line| line.to_string()),
    );
  } else {
    // Check that the subsequent lines match the patch lines
    if !subsequent_lines_match {
      return Err(PatchError::new("Failed to find patch lines"));
    }

    // Remove the lines
    lines.drain(search_line_index + 1..search_line_index + 1 + patch_lines.len());
  }

  // Convert the lines to a string
  let patched = lines.join("\n");

  return Ok(patched);
}

#[cfg(test)]
mod tests {
  use crate::{PAM_PATCH_LINES, PAM_RAW_SEARCH_PATTERN};

  use super::*;
  use rstest::rstest;

  const BEFORE: &str = r#"#
# /etc/pam.d/common-auth - authentication settings common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of the authentication modules that define
# the central authentication scheme for use on the system
# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the
# traditional Unix authentication mechanisms.
#
# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.
# To take advantage of this, it is recommended that you configure any
# local modules either before or after the default block, and use
# pam-auth-update to manage selection of other modules.  See
# pam-auth-update(8) for details.

# here are the per-package modules (the "Primary" block)
auth    [success=1 default=ignore]      pam_unix.so nullok
# here's the fallback if no module succeeds
auth    requisite                       pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
auth    required                        pam_permit.so
# and here are more per-package modules (the "Additional" block)
# end of pam-auth-update config"#;

  const AFTER: &str = r#"#
# /etc/pam.d/common-auth - authentication settings common to all services
#
# This file is included from other service-specific PAM config files,
# and should contain a list of the authentication modules that define
# the central authentication scheme for use on the system
# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the
# traditional Unix authentication mechanisms.
#
# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.
# To take advantage of this, it is recommended that you configure any
# local modules either before or after the default block, and use
# pam-auth-update to manage selection of other modules.  See
# pam-auth-update(8) for details.

# here are the per-package modules (the "Primary" block)
auth    [success=1 default=ignore]      pam_unix.so nullok
auth    [default=ignore]                pam_oauth.so --mode issue
auth    [success=2 default=ignore]      pam_oauth.so --mode verify
# here's the fallback if no module succeeds
auth    requisite                       pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
auth    required                        pam_permit.so
# and here are more per-package modules (the "Additional" block)
# end of pam-auth-update config"#;

  #[rstest]
  #[case("test1", "^test2$", &["test3"], true, None)]
  #[case("#test1", "^test1$", &["test2"], true, None)]
  #[case("test1", "^test1$", &["test2"], true, Some("test1\ntest2"))]
  #[case("test1\ntest2", "^test1$", &["test2"], true, None)]
  #[case("tes\\\nt1", "^test1$", &["test2"], true, Some("test1\ntest2"))]
  #[case("test1\ntest3", "^test1$", &["test2"], true, Some("test1\ntest2\ntest3"))]
  #[case(BEFORE, PAM_RAW_SEARCH_PATTERN, &PAM_PATCH_LINES, true, Some(AFTER))]
  #[case("test1", "^test2$", &["test3"], false, None)]
  #[case("#test1\ntest2", "^test1$", &["test2"], false, None)]
  #[case("test1\ntest2", "^test1$", &["test2"], false, Some("test1"))]
  #[case("tes\\\nt1\ntest2", "^test1$", &["test2"], false, Some("test1"))]
  #[case("test1\ntest2\ntest3", "^test1$", &["test2"], false, Some("test1\ntest3"))]
  #[case(AFTER, PAM_RAW_SEARCH_PATTERN, &PAM_PATCH_LINES, false, Some(BEFORE))]
  fn test_patch_pam(
    #[case] raw: &str,
    #[case] raw_search_pattern: &str,
    #[case] patch_lines: &[&str],
    #[case] add: bool,
    #[case] expected: Option<&str>,
  ) {
    match (
      patch_pam(
        raw,
        &Regex::new(raw_search_pattern).unwrap(),
        patch_lines,
        add,
      ),
      expected,
    ) {
      (Ok(actual), Some(expected)) => {
        assert_eq!(actual, expected);
      }
      (Err(_), None) => {}
      (actual, expected) => {
        panic!("Expected {:?} but got {:?}", expected, actual);
      }
    }
  }
}
