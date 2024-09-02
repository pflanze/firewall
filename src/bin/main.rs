use anyhow::Result;
use firewall::iptables::{Action, Filter, IptablesWriter, Rule};
use firewall::network_interfaces::find_network_interfaces;

fn main() -> Result<()> {
    let mut writer = IptablesWriter::new();
    let action = Action::A;
    let interfaces = find_network_interfaces()?;
    dbg!(&interfaces);

    for chain in [Filter::INPUT, Filter::FORWARD] {
        writer.push(
            Action::I(0),
            Rule {
                chain: chain.into(),
                code: "-j hello".into(),
            },
        );
    }
    for interface in interfaces {
        writer.push(
            action,
            Rule {
                chain: Filter::Custom("hello".into()).into(),
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
                chain: Filter::Custom("hello".into()).into(),
                code: ["-i", &interface, "-j", "REJECT"].as_ref().into(),
            },
        );
    }

    // println!("{}", writer.to_string());
    writer.execute(true, false)
}
