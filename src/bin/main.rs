use anyhow::{bail, Result};
use clap::Parser;
use firewall::iptables::{
    Action, Effect, Filter, IptablesWriter, RecreatingMode, Restriction, Rule, RuleAction,
};
use firewall::network_interfaces::find_network_interfaces;

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

fn main() -> Result<()> {
    let args: Args = Args::parse();

    let want = match &*args.action {
        "start" | "restart" => Effect::Recreation,
        "stop" => Effect::Deletion,
        _ => bail!("invalid action {:?}", args.action),
    };

    let mut iptables = IptablesWriter::new(vec!["ip6tables".into()]);
    let interfaces = if args.interfaces.is_empty() {
        find_network_interfaces()?
    } else {
        args.interfaces
    };

    let our_chain = Filter::Custom("our-chain".into());

    iptables.push(
        Action::NewChain,
        Rule {
            chain: our_chain.clone(),
            restrictions: vec![],
            rule_action: RuleAction::None,
        },
        RecreatingMode::Owned,
    )?;

    for chain in [Filter::INPUT, Filter::FORWARD] {
        iptables.push(
            Action::Insert(1),
            Rule {
                chain: chain.clone(),
                restrictions: vec![],
                rule_action: RuleAction::Goto(our_chain.clone()),
            },
            RecreatingMode::Owned,
        )?;
    }

    for interface in interfaces {
        for port in [22, 80, 9080] {
            iptables.push(
                Action::Append,
                Rule {
                    chain: our_chain.clone(),
                    restrictions: vec![
                        Restriction::Interface(interface.clone()),
                        Restriction::Protocol("tcp"),
                        Restriction::DestinationPort(port),
                    ],
                    rule_action: RuleAction::Return,
                },
                RecreatingMode::Owned,
            )?;
        }
        iptables.push(
            Action::Append,
            Rule {
                chain: our_chain.clone(),
                restrictions: vec![Restriction::Interface(interface.clone())],
                rule_action: RuleAction::Reject,
            },
            RecreatingMode::Owned,
        )?;
    }

    // println!("{}", writer.to_string());
    iptables.execute(want, args.dry_run || args.verbose, !args.dry_run)
}
