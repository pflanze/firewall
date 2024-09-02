use anyhow::Result;
use firewall::iptables::{Action, Filter, IptablesWriter, Rule};
use firewall::network_interfaces::find_network_interfaces;

fn main() -> Result<()> {
    let mut writer = IptablesWriter::new();
    let action = Action::A;
    let interfaces = find_network_interfaces()?;
    dbg!(&interfaces);

    let our_chain = Filter::Custom("our-chain".into());

    writer.push_recreate(
        Action::NewChain,
        Rule {
            chain: our_chain.clone().into(),
            code: "".into(),
        },
    );

    for chain in [Filter::INPUT, Filter::FORWARD] {
        writer.push_recreate(
            Action::I(0),
            Rule {
                chain: chain.into(),
                code: format!("-j {}", our_chain.chain_name_for_same_table_as(&our_chain)).into(),
            },
        );
    }

    for interface in interfaces {
        // Our chain was recreated above, thus `push` suffices here,
        // `push_recreate` is not needed.
        writer.push(
            action,
            Rule {
                chain: our_chain.clone().into(),
                code: [
                    "-i", &interface, "-p", "tcp", "--dport", "9080", "-j", "RETURN",
                ]
                .as_ref()
                .into(),
            },
        );
        writer.push(
            action,
            Rule {
                chain: our_chain.clone().into(),
                code: ["-i", &interface, "-j", "REJECT"].as_ref().into(),
            },
        );
    }

    // println!("{}", writer.to_string());
    writer.execute(true, false)
}
