/// Error when patching
#[derive(Clone, Debug)]
pub struct PatchError {
  message: String,
}

impl PatchError {
  /// Create a new patch error
  pub fn new(message: &str) -> PatchError {
    PatchError {
      message: message.to_string(),
    }
  }
}

impl std::fmt::Display for PatchError {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    write!(f, "{}", self.message)
  }
}

/// Split lines with support for backslash line extensions
pub fn split_lines_with_extensions(raw: &str) -> Vec<String> {
  raw.lines().fold(vec![], |mut acc, line| {
    if let Some(last) = acc.last_mut() {
      if last.ends_with('\\') {
        // Extended line
        last.pop();
        last.push_str(line.trim());
      } else {
        // Regular line
        acc.push(line.trim().to_string());
      }
    } else {
      // Regular line
      acc.push(line.trim().to_string());
    }
    acc
  })
}

#[cfg(test)]
mod tests {

  use super::*;
  use rstest::rstest;

  #[rstest]
  #[case("foo\nbar\nbaz", vec!["foo", "bar", "baz"])]
  #[case("foo\\\nbar\nbaz", vec!["foobar", "baz"])]
  #[case("foo\\\nbar\\\nbaz", vec!["foobarbaz"])]
  #[case("foo\nbar\\", vec!["foo", "bar\\"])]
  fn test_split_lines_with_extensions(#[case] raw: &str, #[case] expected: Vec<&str>) {
    let actual = split_lines_with_extensions(raw);
    assert_eq!(actual, expected);
  }
}
