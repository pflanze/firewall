use anyhow::{bail, Result};
use clap::Parser;
use firewall::iptables::{Action, Effect, Filter, IptablesWriter, Rule};
use firewall::network_interfaces::find_network_interfaces;

#[derive(clap::Parser)]
struct Args {
    /// only show, don't do
    #[clap(short, long)]
    dry_run: bool,

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

    let mut writer = IptablesWriter::new(vec!["ip6tables".into()]);
    let interfaces = find_network_interfaces()?;
    dbg!(&interfaces);

    let our_chain = Filter::Custom("our-chain".into());

    writer.push_wanting(
        want,
        Action::NewChain,
        Rule {
            chain: our_chain.clone().into(),
            code: "".into(),
        },
    );

    for chain in [Filter::INPUT, Filter::FORWARD] {
        writer.push_wanting(
            want,
            Action::Insert(0),
            Rule {
                chain: chain.clone().into(),
                code: ["-j", &our_chain.ensuring_same_table_as(&chain).chain_name()].into(),
            },
        );
    }

    if want != Effect::Deletion {
        for interface in interfaces {
            // Our chain was recreated above, thus `push` would suffice
            // here, but for "stop" we need to revert, so use it
            // anyway. Instead, run this conditionally to avoid errors
            // about the non-existing chain.
            writer.push_wanting(
                want,
                Action::Append,
                Rule {
                    chain: our_chain.clone().into(),
                    code: [
                        "-i", &interface, "-p", "tcp", "--dport", "9080", "-j", "RETURN",
                    ]
                    .into(),
                },
            );
            writer.push_wanting(
                want,
                Action::Append,
                Rule {
                    chain: our_chain.clone().into(),
                    code: ["-i", &interface, "-j", "REJECT"].into(),
                },
            );
        }
    }

    // println!("{}", writer.to_string());
    writer.execute(args.dry_run, !args.dry_run)
}
