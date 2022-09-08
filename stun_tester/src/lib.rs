mod testing;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

pub struct StunTestConfig<'a> {
    hostname: &'a str,
    port: u16,
    ipv4_iface_addr: Option<SocketAddrV4>, // None to disable testing
    ipv6_iface_addr: Option<SocketAddrV6>, // None to disable testing
    test_all_ip_addrs: bool,
    tcp_enabled: bool,
    udp_enabled: bool,
    test_needs_cookie: bool,
    test_change_request: bool,
    timeout: Option<Duration>,
}

pub struct StunTestResult {
    pub supports_ipv4: Option<bool>, // None if not tested
    pub supports_ipv6: Option<bool>, // None if not tested
    pub highly_available_ipv4: Option<bool>, // None if not tested
    pub highly_available_ipv6: Option<bool>, // None if not tested
    pub ipv4_addrs: Vec<Ipv4Addr>,
    pub ipv6_addrs: Vec<Ipv6Addr>,
    // if only one ip is tested, it will be the first one from the list
    pub avg_rtt: Duration,
    pub supports_udp: Option<bool>, // None if not tested
    pub supports_tcp: Option<bool>, // None if not tested
    pub returns_0s: bool,
    pub returns_mapped_address: bool,
    pub returns_xor_mapped_address: bool,
    pub returns_software: Option<String>,
    pub supports_change_request: Option<bool> // None if not tested
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use super::*;

    #[test]
    fn display_result() {

    }
}
