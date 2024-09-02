use anyhow::Result;
use firewall::iptables::{Action, Chain, Filter, IptablesWriter, Rule};
use firewall::network_interfaces::find_network_interfaces;

fn main() -> Result<()> {
    let mut writer = IptablesWriter::new();
    let action = Action::A;
    let interfaces = find_network_interfaces()?;
    dbg!(&interfaces);

    let our_chain: Chain = Filter::Custom("our-chain".into()).into();

    writer.push_recreate_chain(Rule {
        chain: our_chain.clone(),
        code: "".into(),
    });

    for chain in [Filter::INPUT, Filter::FORWARD] {
        writer.push(
            Action::I(0),
            Rule {
                chain: chain.into(),
                code: format!("-j {}", our_chain.table_and_chain_names().1).into(),
            },
        );
    }
    for interface in interfaces {
        writer.push(
            action,
            Rule {
                chain: our_chain.clone(),
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
                chain: our_chain.clone(),
                code: ["-i", &interface, "-j", "REJECT"].as_ref().into(),
            },
        );
    }

    // println!("{}", writer.to_string());
    writer.execute(true, false)
}
