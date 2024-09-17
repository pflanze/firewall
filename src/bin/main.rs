use std::io::stderr;

use anyhow::{bail, Result};
use clap::Parser;
use firewall::executor::{DryExecutor, Executor, ExecutorResult, ExecutorStatus, RealExecutor};
use firewall::iptables::{
    Action, AnyAction, Effect, Filter, IptablesWriter, RecreatingMode, Rule, RuleAction,
};
use firewall::network_interfaces::find_network_interfaces;
use firewall::restrictions;

#[derive(clap::Parser)]
struct Args {
    /// only show, don't do
    #[clap(short, long)]
    dry_run: bool,

    /// always show
    #[clap(short, long)]
    verbose: bool,

    /// instead of running over all auto-detected ethernet interfaces,
    /// run for these specified interfaces.
    #[clap(short, long, multiple(true))]
    interfaces: Vec<String>,

    /// 'start', 'stop', or 'restart'
    action: String,
}

fn example(interfaces: Vec<String>) -> IptablesWriter {
    let mut iptables = IptablesWriter::new(vec!["ip6tables".into()]);
    let our_chain = Filter::Custom("our-chain".into());

    iptables.push(
        Action::NewChain,
        Rule {
            chain: our_chain.clone(),
            restrictions: vec![],
            rule_action: RuleAction::None,
        },
        RecreatingMode::Owned,
    );

    for chain in [Filter::INPUT, Filter::FORWARD] {
        iptables.push(
            Action::Insert(1),
            Rule {
                chain: chain.clone(),
                restrictions: vec![],
                rule_action: RuleAction::Jump(our_chain.clone()),
            },
            RecreatingMode::Owned,
        )
    }

    for interface in interfaces {
        for port in [22, 80, 9080] {
            iptables.push(
                Action::Append,
                Rule {
                    chain: our_chain.clone(),
                    restrictions: restrictions![
                        Interface(Is, interface.clone()),
                        Protocol(Is, Tcp),
                        DestinationPort(Is, port),
                    ],
                    rule_action: RuleAction::Return,
                },
                RecreatingMode::Owned,
            )
        }
        iptables.push(
            Action::Append,
            Rule {
                chain: our_chain.clone(),
                restrictions: restrictions![Interface(Is, interface.clone()),],
                rule_action: RuleAction::Reject,
            },
            RecreatingMode::Owned,
        )
    }

    iptables
}

fn main() -> Result<()> {
    let args: Args = Args::parse();

    let want = match &*args.action {
        "start" | "restart" => Effect::Recreation,
        "stop" => Effect::Deletion,
        _ => bail!("invalid action {:?}", args.action),
    };

    let interfaces = if args.interfaces.is_empty() {
        find_network_interfaces()?
    } else {
        args.interfaces
    };

    let mut executor: Box<dyn Executor<AnyAction>> = if args.dry_run {
        Box::new(DryExecutor)
    } else {
        Box::new(RealExecutor)
    };
    let verbose = args.dry_run || args.verbose;
    let verbose_output = if verbose { Some(stderr()) } else { None };
    example(interfaces).execute(want, verbose_output, &mut *executor)
}

// =============================================================================
// Tests that want to be based on the above `example` rules:

struct MockExecutor(Vec<(&'static str, ExecutorStatus, String)>);

impl Executor<AnyAction> for MockExecutor {
    fn execute<'t>(&mut self, _action: AnyAction, cmd: &'t [String]) -> ExecutorResult<'t> {
        for (arg, status, output) in &self.0 {
            if cmd.contains(&String::from(*arg)) {
                return ExecutorResult {
                    cmd,
                    status: status.clone(),
                    combined_output: output.clone(),
                };
            }
        }
        ExecutorResult {
            cmd,
            status: ExecutorStatus::Success,
            combined_output: "".into(),
        }
    }
}

#[test]
fn verify_error_mode() {
    use indoc::indoc;

    let run = |mut executor: MockExecutor| -> Result<String> {
        let iptables = example(vec!["eth42".into()]);
        let mut output = Vec::new();
        iptables.execute(Effect::Recreation, Some(&mut output), &mut executor)?;
        Ok(String::from_utf8(output).unwrap())
    };

    assert_eq!(
        run(MockExecutor(vec![
            // code 1 would happen if the chain didn't exist (OK, -F
            // should also fail, then)
            ("-X", ExecutorStatus::ExitCode(1), "".into()),
        ]))
        .unwrap(),
        indoc! {"
            + ip6tables -t filter -D our-chain -i eth42 -j REJECT
            + ip6tables -t filter -D our-chain -i eth42 -p tcp --dport 9080 -j RETURN
            + ip6tables -t filter -D our-chain -i eth42 -p tcp --dport 80 -j RETURN
            + ip6tables -t filter -D our-chain -i eth42 -p tcp --dport 22 -j RETURN
            + ip6tables -t filter -D FORWARD -j our-chain
            + ip6tables -t filter -D INPUT -j our-chain
            + ip6tables -t filter -F our-chain
            E ip6tables -t filter -X our-chain
            + ip6tables -t filter -N our-chain
            + ip6tables -t filter -I INPUT 1 -j our-chain
            + ip6tables -t filter -I FORWARD 1 -j our-chain
            + ip6tables -t filter -A our-chain -i eth42 -p tcp --dport 22 -j RETURN
            + ip6tables -t filter -A our-chain -i eth42 -p tcp --dport 80 -j RETURN
            + ip6tables -t filter -A our-chain -i eth42 -p tcp --dport 9080 -j RETURN
            + ip6tables -t filter -A our-chain -i eth42 -j REJECT
        "}
    );

    assert_eq!(
        run(MockExecutor(vec![
            // code 4 happens if the chain can't be removed because it
            // is still "in use", but in this case iptables also
            // prints a message saying so. We're not giving that
            // message so we expect an error.
            ("-X", ExecutorStatus::ExitCode(4), "".into()),
        ]))
        .unwrap_err()
        .to_string(),
        "command `ip6tables -t filter -X our-chain` exited with code 4: "
    );

    // Simulate chain deletion failure because of it being busy; but
    // do not simulate the subsequent error on the -N action--for that
    // see the next test.
    assert_eq!(
        run(MockExecutor(vec![(
            "-X",
            ExecutorStatus::ExitCode(4),
            ".. CHAIN_DEL failed (Device or resource busy) ..".into()
        ),]))
        .unwrap(),
        indoc! {"
            + ip6tables -t filter -D our-chain -i eth42 -j REJECT
            + ip6tables -t filter -D our-chain -i eth42 -p tcp --dport 9080 -j RETURN
            + ip6tables -t filter -D our-chain -i eth42 -p tcp --dport 80 -j RETURN
            + ip6tables -t filter -D our-chain -i eth42 -p tcp --dport 22 -j RETURN
            + ip6tables -t filter -D FORWARD -j our-chain
            + ip6tables -t filter -D INPUT -j our-chain
            + ip6tables -t filter -F our-chain
            E ip6tables -t filter -X our-chain
            + ip6tables -t filter -N our-chain
            + ip6tables -t filter -I INPUT 1 -j our-chain
            + ip6tables -t filter -I FORWARD 1 -j our-chain
            + ip6tables -t filter -A our-chain -i eth42 -p tcp --dport 22 -j RETURN
            + ip6tables -t filter -A our-chain -i eth42 -p tcp --dport 80 -j RETURN
            + ip6tables -t filter -A our-chain -i eth42 -p tcp --dport 9080 -j RETURN
            + ip6tables -t filter -A our-chain -i eth42 -j REJECT
        "}
    );

    // Simulate chain deletion failure because of it being busy,
    // including subsequent error on -N action.
    assert_eq!(
        run(MockExecutor(vec![
            (
                "-X",
                ExecutorStatus::ExitCode(4),
                ".. CHAIN_DEL failed (Device or resource busy) ..".into()
            ),
            (
                "-N",
                ExecutorStatus::ExitCode(1),
                "iptables: Chain already exists.".into()
            )
        ]))
        .unwrap(),
        indoc! {"
            + ip6tables -t filter -D our-chain -i eth42 -j REJECT
            + ip6tables -t filter -D our-chain -i eth42 -p tcp --dport 9080 -j RETURN
            + ip6tables -t filter -D our-chain -i eth42 -p tcp --dport 80 -j RETURN
            + ip6tables -t filter -D our-chain -i eth42 -p tcp --dport 22 -j RETURN
            + ip6tables -t filter -D FORWARD -j our-chain
            + ip6tables -t filter -D INPUT -j our-chain
            + ip6tables -t filter -F our-chain
            E ip6tables -t filter -X our-chain
            E ip6tables -t filter -N our-chain
            + ip6tables -t filter -I INPUT 1 -j our-chain
            + ip6tables -t filter -I FORWARD 1 -j our-chain
            + ip6tables -t filter -A our-chain -i eth42 -p tcp --dport 22 -j RETURN
            + ip6tables -t filter -A our-chain -i eth42 -p tcp --dport 80 -j RETURN
            + ip6tables -t filter -A our-chain -i eth42 -p tcp --dport 9080 -j RETURN
            + ip6tables -t filter -A our-chain -i eth42 -j REJECT
        "}
    );
}

#[test]
fn test_restriction_common() {
    use indoc::indoc;

    let mut iptables = IptablesWriter::new(vec!["ip6tables".into()]);
    iptables.push(
        Action::Append,
        Rule {
            chain: Filter::INPUT,
            restrictions: restrictions![Custom(vec![
                "-m".to_string(),
                "conntrack".to_string(),
                "--ctstate".to_string(),
                "RELATED,ESTABLISHED".to_string(),
            ])],
            // XX todo: is it valid to not have an action?
            rule_action: RuleAction::None,
        },
        RecreatingMode::Owned,
    );
    let mut output = Vec::new();
    iptables
        .execute(Effect::Recreation, Some(&mut output), &mut DryExecutor)
        .unwrap();
    let output = String::from_utf8(output).unwrap();
    assert_eq!(
        output,
        indoc! {"
            + ip6tables -t filter -D INPUT -m conntrack --ctstate RELATED,ESTABLISHED
            + ip6tables -t filter -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED
        "}
    );
}
