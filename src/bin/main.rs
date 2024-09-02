use anyhow::Result;
use firewall::iptables::{IptablesWriter, Action, Rule, Filter};



fn main() -> Result<()> {
    let mut writer = IptablesWriter::new();
    let action = Action::A;
    let interfaces = vec!("eth0", "eth1"); // XX detect

    for chain in [Filter::INPUT, Filter::FORWARD] {
        writer.push(Action::I(0), Rule {
            chain: chain.into(),
            code: "-j hello".into()
        });
    }
    for interface in interfaces {
        writer.push(action, Rule {
            chain: Filter::Custom("hello".into()).into(),
            code: ["-i", interface, "-p", "tcp", "--dport", "9080", "-j", "RETURN"].as_ref().into()
        });
        writer.push(action, Rule {
            chain: Filter::Custom("hello".into()).into(),
            code: ["-i", interface, "-j", "REJECT"].as_ref().into()
        });
    }

    // println!("{}", writer.to_string());
    writer.execute(true, false)
}
