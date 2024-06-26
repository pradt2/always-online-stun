use std::collections::HashSet;
use std::io;
use rand::prelude::SliceRandom;
use rand::thread_rng;
use crate::StunServerTestResult;
use crate::utils::ReduceToString;

pub(crate) struct ValidHosts<'a> {
    server_test_results: &'a Vec<StunServerTestResult>,
    file_path: String,
    check_nat_testing: bool,
}

impl ValidHosts<'_> {
    pub(crate) fn udp(server_test_results: &Vec<StunServerTestResult>) -> ValidHosts {
        ValidHosts {
            server_test_results,
            file_path: String::from("valid_hosts.txt"),
            check_nat_testing: false,
        }
    }

    pub(crate) fn udp_with_nat_testing(server_test_results: &Vec<StunServerTestResult>) -> ValidHosts {
        ValidHosts {
            server_test_results,
            file_path: String::from("valid_nat_testing_hosts.txt"),
            check_nat_testing: true,
        }
    }

    pub(crate) fn tcp(server_test_results: &Vec<StunServerTestResult>) -> ValidHosts {
        ValidHosts {
            server_test_results,
            file_path: String::from("valid_hosts_tcp.txt"),
            check_nat_testing: false,
        }
    }

    pub(crate) fn tcp_with_nat_testing(server_test_results: &Vec<StunServerTestResult>) -> ValidHosts {
        ValidHosts {
            server_test_results,
            file_path: String::from("valid_nat_testing_hosts_tcp.txt"),
            check_nat_testing: true,
        }
    }

    pub(crate) fn get_output(&self) -> String {
        let mut output = self.server_test_results.iter()
            .filter(|server_test_result| server_test_result.is_healthy())
            .filter(|server_test_result| if self.check_nat_testing { server_test_result.is_nat_testing_supported() } else { true })
            .map(|server_test_result| {
                let _proto = server_test_result.server.protocol;
                let host= server_test_result.server.hostname.as_str();
                let port = server_test_result.server.port;
                format!("{}:{}\n", host, port)
            })
            .collect::<Vec<_>>();
        output.shuffle(&mut thread_rng());

        let output = output.iter().reduce_to_string();
        output
    }

    pub(crate) async fn save(&self) -> io::Result<()> {
        let output = self.get_output();
        tokio::fs::write(self.file_path.as_str(), output).await
    }
}

pub(crate) struct ValidIpV4s<'a> {
    server_test_results: &'a Vec<StunServerTestResult>,
    file_path: String,
    check_nat_testing: bool,
}

impl ValidIpV4s<'_> {
    pub(crate) fn udp(server_test_results: &Vec<StunServerTestResult>) -> ValidIpV4s {
        ValidIpV4s {
            server_test_results,
            file_path: String::from("valid_ipv4s.txt"),
            check_nat_testing: false,
        }
    }

    pub(crate) fn udp_with_nat_testing(server_test_results: &Vec<StunServerTestResult>) -> ValidIpV4s {
        ValidIpV4s {
            server_test_results,
            file_path: String::from("valid_nat_testing_ipv4s.txt"),
            check_nat_testing: true,
        }
    }

    pub(crate) fn tcp(server_test_results: &Vec<StunServerTestResult>) -> ValidIpV4s {
        ValidIpV4s {
            server_test_results,
            file_path: String::from("valid_ipv4s_tcp.txt"),
            check_nat_testing: false,
        }
    }

    pub(crate) fn tcp_with_nat_testing(server_test_results: &Vec<StunServerTestResult>) -> ValidIpV4s {
        ValidIpV4s {
            server_test_results,
            file_path: String::from("valid_nat_testing_ipv4s_tcp.txt"),
            check_nat_testing: true,
        }
    }

    pub(crate) fn get_output(&self) -> String {
        let mut output = self.server_test_results.iter()
            .filter(|server_test_result| server_test_result.is_healthy())
            .flat_map(|server_test_result| {
                let ipv4s = server_test_result.socket_tests.iter()
                    .filter(|socket_test| socket_test.socket.is_ipv4())
                    .filter(|socket_test| if self.check_nat_testing { socket_test.is_nat_testing_supported() } else { true })
                    .map(|socket_test| format!("{}\n", socket_test.socket));
                ipv4s
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        output.shuffle(&mut thread_rng());

        let output = output.iter().reduce_to_string();
        output
    }

    pub(crate) async fn save(&self) -> io::Result<()> {
        let output = self.get_output();
        tokio::fs::write(self.file_path.as_str(), output).await
    }
}

pub(crate) struct ValidIpV6s<'a> {
    server_test_results: &'a Vec<StunServerTestResult>,
    file_path: String,
    check_nat_testing: bool,
}

impl ValidIpV6s<'_> {
    pub(crate) fn udp(server_test_results: &Vec<StunServerTestResult>) -> ValidIpV6s {
        ValidIpV6s {
            server_test_results,
            file_path: String::from("valid_ipv6s.txt"),
            check_nat_testing: false,
        }
    }

    pub(crate) fn udp_with_nat_testing(server_test_results: &Vec<StunServerTestResult>) -> ValidIpV6s {
        ValidIpV6s {
            server_test_results,
            file_path: String::from("valid_nat_testing_ipv6s.txt"),
            check_nat_testing: true,
        }
    }

    pub(crate) fn tcp(server_test_results: &Vec<StunServerTestResult>) -> ValidIpV6s {
        ValidIpV6s {
            server_test_results,
            file_path: String::from("valid_ipv6s_tcp.txt"),
            check_nat_testing: false,
        }
    }

    pub(crate) fn tcp_with_nat_testing(server_test_results: &Vec<StunServerTestResult>) -> ValidIpV6s {
        ValidIpV6s {
            server_test_results,
            file_path: String::from("valid_nat_testing_ipv6s_tcp.txt"),
            check_nat_testing: true,
        }
    }

    pub(crate) fn get_output(&self) -> String {
        let mut output = self.server_test_results.iter()
            .filter(|server_test_result| server_test_result.is_healthy())
            .flat_map(|server_test_result| {
                let ipv4s = server_test_result.socket_tests.iter()
                    .filter(|socket_test| socket_test.socket.is_ipv6())
                    .filter(|socket_test| if self.check_nat_testing { socket_test.is_nat_testing_supported() } else { true })
                    .map(|socket_test| format!("{}\n", socket_test.socket));
                ipv4s
            })
            .collect::<Vec<_>>();
        output.shuffle(&mut thread_rng());

        let output = output.iter().reduce_to_string();
        output
    }

    pub(crate) async fn save(&self) -> io::Result<()> {
        let output = self.get_output();
        tokio::fs::write(self.file_path.as_str(), output).await
    }
}
