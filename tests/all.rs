use std::process::Command;

use anyhow::{anyhow, Context, Result};
use indoc::indoc;

#[test]
fn verify_verbose_output() -> Result<()> {
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
    let expected_stderr = indoc! {"
        + ip6tables -t filter -D our-chain -i eth0 -j REJECT
        + ip6tables -t filter -D our-chain -i eth0 -p tcp --dport 9080 -j RETURN
        + ip6tables -t filter -D our-chain -i eth0 -p tcp --dport 80 -j RETURN
        + ip6tables -t filter -D our-chain -i eth0 -p tcp --dport 22 -j RETURN
        + ip6tables -t filter -D FORWARD -j our-chain
        + ip6tables -t filter -D INPUT -j our-chain
        + ip6tables -t filter -F our-chain
        + ip6tables -t filter -X our-chain
        + ip6tables -t filter -N our-chain
        + ip6tables -t filter -I INPUT 1 -j our-chain
        + ip6tables -t filter -I FORWARD 1 -j our-chain
        + ip6tables -t filter -A our-chain -i eth0 -p tcp --dport 22 -j RETURN
        + ip6tables -t filter -A our-chain -i eth0 -p tcp --dport 80 -j RETURN
        + ip6tables -t filter -A our-chain -i eth0 -p tcp --dport 9080 -j RETURN
        + ip6tables -t filter -A our-chain -i eth0 -j REJECT
    "};
    assert_eq!(stderr, expected_stderr);

    Ok(())
}
