use std::collections::HashSet;

use regex::Regex;

use crate::utils::PatchError;

/// Patch an NSS file by appending the patch source before the search database
pub fn patch_nss(
  raw: &str,
  search_databases: &HashSet<&str>,
  patch_source: &str,
  add: bool,
) -> Result<String, PatchError> {
  let line_pattern =
    Regex::new(r"^(?<database_with_extra>(?<database>\w+):\s*)(?<rest>.*)$").unwrap();
  let rest_pattern = Regex::new(r"(?<source>\w+)").unwrap();

  // Split the file into lines
  let mut lines = raw.lines().map(|line| line.to_string()).collect::<Vec<_>>();

  // Iterate over the lines
  let mut found = false;

  for line_index in 0..lines.len() {
    // Get the line
    let line = &lines[line_index];

    // Parse the line
    let line_captures = match line_pattern.captures(&line) {
      Some(captures) => captures,
      None => {
        // Skip if the line does not match the pattern
        continue;
      }
    };

    // Skip if the database is not in the search databases
    if !search_databases.contains(&line_captures["database"]) {
      continue;
    }

    // Get the database_with_extra capture
    let database_with_extra_capture = line_captures
      .name("database_with_extra")
      .ok_or(PatchError::new("Failed to get database_with_extra capture"))?;

    let database_with_extra_ends_with_whitespace = database_with_extra_capture
      .as_str()
      .chars()
      .last()
      .ok_or(PatchError::new(
        "Failed to get last character of database_with_extra capture",
      ))?
      .is_whitespace();

    // Parse the rest of the line
    let rest_capture = rest_pattern
      .captures_iter(&line_captures["rest"])
      .collect::<Vec<_>>();

    // Check if the source is already in the line
    let source_already_present = rest_capture
      .iter()
      .any(|captures| captures["source"] == *patch_source);

    // Patch the line
    let patched_line = if add {
      // Check that the source is not already present
      if source_already_present {
        return Err(PatchError::new("Already patched"));
      }

      // Insert the source
      line[..database_with_extra_capture.end()].to_string()
        + if database_with_extra_ends_with_whitespace {
          ""
        } else {
          " "
        }
        + patch_source
        + if rest_capture.is_empty() { "" } else { " " }
        + &line[database_with_extra_capture.end()..]
    } else {
      // Get the patch source capture
      if let Some(patch_source_capture_index) = rest_capture
        .iter()
        .position(|captures| captures["source"] == *patch_source)
      {
        // Check that the source is present
        if !source_already_present {
          return Err(PatchError::new("Failed to find patch source"));
        }

        line[..database_with_extra_capture.len()
          + rest_capture[patch_source_capture_index]
            .name("source")
            .ok_or(PatchError::new("Failed to get source capture"))?
            .start()]
          .to_string()
          + if database_with_extra_ends_with_whitespace || rest_capture.len() <= 1 {
            ""
          } else {
            " "
          }
          + if rest_capture.len() > 1 {
            &line[database_with_extra_capture.len()
              + rest_capture[patch_source_capture_index + 1]
                .name("source")
                .ok_or(PatchError::new("Failed to get source capture"))?
                .start()..]
          } else {
            ""
          }
      } else {
        continue;
      }
    };

    // Replace the line
    lines[line_index] = patched_line;

    found = true;
  }

  if !found {
    return Err(PatchError::new(&format!(
      "Failed to find search databases: {:?}",
      search_databases
    )));
  }

  // Convert the lines to a string
  let patched = lines.join("\n");

  return Ok(patched);
}

#[cfg(test)]
mod tests {
  use crate::{NSS_PATCH_SOURCE, NSS_SEARCH_DATABASES};

  use super::*;
  use rstest::rstest;

  const BEFORE: &str = r#"# /etc/nsswitch.conf
#
# Example configuration of GNU Name Service Switch functionality.
# If you have the `glibc-doc-reference' and `info' packages installed, try:
# `info libc "Name Service Switch"' for information about this file.

passwd:         files
group:          files
shadow:         files
gshadow:        files

hosts:          files dns
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis"#;

  const AFTER: &str = r#"# /etc/nsswitch.conf
#
# Example configuration of GNU Name Service Switch functionality.
# If you have the `glibc-doc-reference' and `info' packages installed, try:
# `info libc "Name Service Switch"' for information about this file.

passwd:         oauth files
group:          oauth files
shadow:         oauth files
gshadow:        oauth files

hosts:          files dns
networks:       files

protocols:      db files
services:       db files
ethers:         db files
rpc:            db files

netgroup:       nis"#;

  #[rstest]
  #[case("test1:", HashSet::from(["test2"]), "test3", true, None)]
  #[case("#test1:", HashSet::from(["test1"]), "test3", true, None)]
  #[case("test1:", HashSet::from(["test1"]), "test3", true, Some("test1: test3"))]
  #[case("test1: test3", HashSet::from(["test1"]), "test3", true, None)]
  #[case("test1: ", HashSet::from(["test1"]), "test3", true, Some("test1: test3"))]
  #[case("test1:    ", HashSet::from(["test1"]), "test3", true, Some("test1:    test3"))]
  #[case("test1: test2", HashSet::from(["test1"]), "test3", true, Some("test1: test3 test2"))]
  #[case("test1: test2    ", HashSet::from(["test1"]), "test3", true, Some("test1: test3 test2    "))]
  #[case("test1:     test2", HashSet::from(["test1"]), "test3", true, Some("test1:     test3 test2"))]
  #[case(
    BEFORE,
    HashSet::from(NSS_SEARCH_DATABASES),
    NSS_PATCH_SOURCE,
    true,
    Some(AFTER)
  )]
  #[case("test1:", HashSet::from(["test2"]), "test3", false, None)]
  #[case("#test1:", HashSet::from(["test1"]), "test3", false, None)]
  #[case("test1:test3", HashSet::from(["test1"]), "test3", false, Some("test1:"))]
  #[case("test1: test3", HashSet::from(["test1"]), "test3", false, Some("test1: "))]
  #[case("test1:    test3", HashSet::from(["test1"]), "test3", false, Some("test1:    "))]
  #[case("test1: test3 test2", HashSet::from(["test1"]), "test3", false, Some("test1: test2"))]
  #[case("test1: test3 test2    ", HashSet::from(["test1"]), "test3", false, Some("test1: test2    "))]
  #[case("test1:     test3 test2", HashSet::from(["test1"]), "test3", false, Some("test1:     test2"))]
  #[case(
    AFTER,
    HashSet::from(NSS_SEARCH_DATABASES),
    NSS_PATCH_SOURCE,
    false,
    Some(BEFORE)
  )]
  fn test_patch_nss(
    #[case] raw: &str,
    #[case] search_databases: HashSet<&str>,
    #[case] patch_source: &str,
    #[case] add: bool,
    #[case] expected: Option<&str>,
  ) {
    match (
      patch_nss(raw, &search_databases, patch_source, add),
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
