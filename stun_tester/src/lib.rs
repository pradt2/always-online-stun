use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::time::Duration;

struct StunTestConfig<'a> {
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

struct StunTestResult {
    supports_ipv4: Option<bool>, // None if not tested
    supports_ipv6: Option<bool>, // None if not tested
    highly_available_ipv4: Option<bool>, // None if not tested
    highly_available_ipv6: Option<bool>, // None if not tested
    ipv4_addrs: Vec<Ipv4Addr>,
    ipv6_addrs: Vec<Ipv6Addr>,
    // if only one ip is tested, it will be the first one from the list
    avg_rtt: Duration,
    supports_udp: Option<bool>, // None if not tested
    supports_tcp: Option<bool>, // None if not tested
    returns_0s: bool,
    returns_mapped_address: bool,
    returns_xor_mapped_address: bool,
    returns_software: Option<String>,
    supports_change_request: Option<bool> // None if not tested
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use super::*;

    #[test]
    fn display_result() {

        let hostname = "stun.stunprotocol.org";
        let port = 3478;

        let result = StunTestResult {
            supports_ipv4: Some(true),
            supports_ipv6: Some(true),
            highly_available_ipv4: Some(false),
            highly_available_ipv6: Some(true),
            ipv4_addrs: vec![Ipv4Addr::new(127,0,0,1), Ipv4Addr::new(128,11,22,250)],
            ipv6_addrs: vec![Ipv6Addr::from(127 << 96 | 65535), Ipv6Addr::from(65535 << 96 | 127)],
            avg_rtt: Duration::from_millis(122),
            supports_udp: Some(true),
            supports_tcp: Some(true),
            returns_0s: false,
            returns_mapped_address: true,
            returns_xor_mapped_address: true,
            returns_software: Some(String::from("AwSTUN Server v1.2")),
            supports_change_request: Some(true),
        };

        // subtle emojis ✔ ✘
        let OK = "✅ ? ✓ ✓ ✓ ✘ ❌ ✖ ✕ ❎ ☓ ✗";
        let FAIL = "❌";
        let BULB = "•";
        let LMARGIN = "   ";

        println!("                         ============ TEST RESULTS ===========");
        println!(" 🌍 {}:{}", hostname, port);
        match result.supports_ipv4 {
            Some(true) => {
                println!("{} {} supports IPv4", LMARGIN, OK);
                match result.highly_available_ipv4 {
                    Some(true) => {
                        println!("{} {} {} and is highly available under these addresses", LMARGIN, LMARGIN, OK);
                    },
                    Some(false) => {
                        println!("{} {} {} but isn't highly available (only address)", LMARGIN, LMARGIN, FAIL);
                    },
                    None => {

                    }
                };
                for addr in &result.ipv4_addrs {
                    println!("{} {} {} {} {:?}", LMARGIN, LMARGIN, LMARGIN, BULB, addr);
                }
            },
            Some(false) => {
                println!("{} {} doesn't support IPv4", LMARGIN, FAIL)
            },
            None => {

            }
        }
        assert!(false);
    }
}