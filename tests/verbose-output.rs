use std::process::Command;

use anyhow::{anyhow, Context, Result};

#[test]
fn test_executable() -> Result<()> {
    let example_name = "main";

    let output = Command::new("cargo")
        .args([
            "run",
            "--quiet",
            "--bin",
            example_name,
            "--",
            "start",
            "--dry-run",
        ])
        .output()
        .with_context(|| anyhow!("running {example_name:?}"))?;

    assert!(output.status.success());

    assert!(output.stdout.len() == 0);

    let stderr = String::from_utf8_lossy(&output.stderr);
    let expected_stderr = include_str!("verbose-output.out");
    assert_eq!(stderr, expected_stderr);

    Ok(())
}
