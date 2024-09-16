use std::io::stderr;

use anyhow::{bail, Result};
use clap::Parser;
use firewall::executor::{DryExecutor, Executor, RealExecutor};
use firewall::iptables::{
    Action, Effect, Filter, IptablesWriter, RecreatingMode, Rule, RuleAction,
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

    iptables
        .push(
            Action::NewChain,
            Rule {
                chain: our_chain.clone(),
                restrictions: vec![],
                rule_action: RuleAction::None,
            },
            RecreatingMode::Owned,
        )
        .unwrap();

    for chain in [Filter::INPUT, Filter::FORWARD] {
        iptables
            .push(
                Action::Insert(1),
                Rule {
                    chain: chain.clone(),
                    restrictions: vec![],
                    rule_action: RuleAction::Jump(our_chain.clone()),
                },
                RecreatingMode::Owned,
            )
            .unwrap();
    }

    for interface in interfaces {
        for port in [22, 80, 9080] {
            iptables
                .push(
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
                .unwrap();
        }
        iptables
            .push(
                Action::Append,
                Rule {
                    chain: our_chain.clone(),
                    restrictions: restrictions![Interface(Is, interface.clone()),],
                    rule_action: RuleAction::Reject,
                },
                RecreatingMode::Owned,
            )
            .unwrap();
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

    let mut executor: Box<dyn Executor<Action>> = if args.dry_run {
        Box::new(DryExecutor)
    } else {
        Box::new(RealExecutor)
    };
    let verbose = args.dry_run || args.verbose;
    let verbose_output = if verbose { Some(stderr()) } else { None };
    example(interfaces).execute(want, verbose_output, &mut *executor)
}
