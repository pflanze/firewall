use anyhow::Result;
use nispor::{IfaceType, NetStateFilter, NetStateIfaceFilter};

pub fn find_network_interfaces() -> Result<Vec<String>> {
    let mut interface_filter = NetStateIfaceFilter::minimum();
    interface_filter.include_ethtool = true;

    let mut filter = NetStateFilter::minimum();
    filter.iface = Some(interface_filter);

    let result = nispor::NetState::retrieve_with_filter(&filter)?;

    let interface_names = result
        .ifaces
        .into_iter()
        .filter(|(_, iface)| iface.iface_type == IfaceType::Ethernet)
        .map(|(_, iface)| iface.name)
        .collect();

    Ok(interface_names)
}
