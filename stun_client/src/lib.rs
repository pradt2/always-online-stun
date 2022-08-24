use std::*;
use std::io::{Read, Write};
use log::error;

mod client;

enum Protocol {
    UDP,
    TCP,
}

enum Conn {
    UDP(net::UdpSocket),
    TCP(net::TcpStream),
}

impl Conn {
    fn connect<T: net::ToSocketAddrs, U: net::ToSocketAddrs>(
        local_addr: T,
        remote_addr: U,
        proto: Protocol,
        timeout: time::Duration,
    ) -> io::Result<Conn> {
        match proto {
            Protocol::UDP => {
                let sock = net::UdpSocket::bind(local_addr)?;
                sock.connect(remote_addr)?;
                Ok(Conn::UDP(sock))
            }
            Protocol::TCP => {
                let remote_addr = remote_addr.to_socket_addrs()?
                    .next()
                    .ok_or(io::Error::new(io::ErrorKind::NotFound, "Address not resolved"))?;
                let stream = net::TcpStream::connect_timeout(&remote_addr, timeout)?;
                Ok(Conn::TCP(stream))
            }
        }
    }
}

impl<'a> From<&'a mut Conn> for ConnRef<'a> {
    fn from(conn: &'a mut Conn) -> Self {
        match conn {
            Conn::UDP(sock) => ConnRef::from(&*sock),
            Conn::TCP(stream) => ConnRef::from(stream),
        }
    }
}

enum ConnRef<'a> {
    UDP(&'a net::UdpSocket),
    TCP(&'a mut net::TcpStream),
}

impl<'a> From<&'a net::UdpSocket> for ConnRef<'a> {
    fn from(sock: &'a net::UdpSocket) -> Self {
        ConnRef::UDP(sock)
    }
}

impl<'a> From<&'a mut net::TcpStream> for ConnRef<'a> {
    fn from(stream: &'a mut net::TcpStream) -> Self {
        ConnRef::TCP(stream)
    }
}

impl<'a> ConnRef<'a> {
    fn read(&mut self, buf: &mut [u8], timeout: time::Duration) -> io::Result<usize> {
        match self {
            ConnRef::UDP(sock) => {
                sock.set_read_timeout(Some(timeout))?;
                sock.recv(buf)
            }
            ConnRef::TCP(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.read(buf)
            }
        }
    }

    fn write(&mut self, buf: &mut [u8], timeout: time::Duration) -> io::Result<usize> {
        match self {
            ConnRef::UDP(sock) => {
                sock.set_write_timeout(Some(timeout))?;
                sock.send(buf)
            }
            ConnRef::TCP(stream) => {
                stream.set_write_timeout(Some(timeout))?;
                stream.write(buf)
            }
        }
    }
}

struct Client {
    timeout: time::Duration,
}

impl Client {
    fn new(timeout: time::Duration) -> Self {
        Self {
            timeout
        }
    }

    fn call_addr<T: net::ToSocketAddrs>(&self, remote_addr: T, proto: Protocol, buf: &mut [u8], msg_size: usize) -> io::Result<usize> {
        let mut conn = Conn::connect("0.0.0.0:0", remote_addr, proto, self.timeout)?;
        self.call_conn(&mut conn, buf, msg_size)
    }

    fn call_conn<'a, T: Into<ConnRef<'a>>>(&self, conn: T, buf: &mut [u8], msg_size: usize) -> io::Result<usize> {
        let mut conn = conn.into();
        let mut bytes_written = 0;
        while bytes_written < msg_size {
            bytes_written += conn.write(&mut buf[bytes_written..msg_size], self.timeout)?;
        };
        conn.read(buf, self.timeout)
    }
}

fn print_stun_msg(buf: &[u8]) {
    use stun_proto::rfc5389::*;

    fn message_type_to_str(typ: Result<MessageType, ReaderErr>) -> &'static str {
        match typ {
            Ok(MessageType::BindingRequest) => "Binding Request",
            Ok(MessageType::BindingResponse) => "Binding Response",
            Ok(MessageType::BindingIndication) => "Binding Indication",
            Ok(MessageType::BindingErrorResponse) => "Binding Error Response",
            Err(ReaderErr::NotEnoughBytes) => "<NOT ENOUGH BYTES>",
            Err(ReaderErr::UnexpectedValue) => "<UNEXPECTED VALUE>",
        }
    }

    let reader = Reader::new(buf);
    error!("Type: {}", message_type_to_str(reader.get_message_type()));
    error!("Len: {}", match reader.get_message_length() { Some(len) => len.to_string(), None => String::from("<NOT ENOUGH BYTES>") });
    error!("Cookie: {}", match reader.get_magic_cookie() { Some(cookie) => format!("{:#01x}", cookie), None => String::from("<NOT ENOUGH BYTES>") });
    error!("Transaction ID: {}", match reader.get_transaction_id() { Some(tid) => format!("{:#01x}", tid), None => String::from("<NOT ENOUGH BYTES>") });

    for attr in reader.get_attributes() {
        match attr {
            Ok(reader) => match reader {
                ReaderAttribute::MappedAddress(r) => match r.get_address() {
                    Ok(SocketAddr::V4(ip, port)) => error!("MAPPED-ADDRESS: {}", net::SocketAddr::new(net::IpAddr::from(ip.to_be_bytes()), port)),
                    Ok(SocketAddr::V6(ip, port)) => error!("MAPPED-ADDRESS: {}", net::SocketAddr::new(net::IpAddr::from(ip.to_be_bytes()), port)),
                    Err(ReaderErr::NotEnoughBytes) => error!("MAPPED-ADDRESS: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => error!("MAPPED-ADDRESS: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::Username(r) => match r.get_value() {
                    Ok(val) => error!("USERNAME: {}", val),
                    Err(ReaderErr::NotEnoughBytes) => error!("USERNAME: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => error!("USERNAME: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::MessageIntegrity(r) => match r.get_value() {
                    Some(val) => error!("MESSAGE-INTEGRITY: {:?}", val),
                    None => error!("MESSAGE-INTEGRITY: <NOT ENOUGH BYTES>"),
                },
                ReaderAttribute::ErrorCode(r) => {
                        let err = match r.get_error() {
                            Ok(code) => code,
                            Err(ReaderErr::NotEnoughBytes) => {
                                error!("ERROR-CODE: err <NOT ENOUGH BYTES>");
                                continue;
                            },
                            Err(ReaderErr::UnexpectedValue) => {
                                error!("ERROR-CODE: err <UNEXPECTED VALUE>");
                                continue;
                            },
                        };
                        let reason = match r.get_reason() {
                            Ok(reason) => reason,
                            Err(ReaderErr::NotEnoughBytes) => {
                                error!("ERROR-CODE: reason <NOT ENOUGH BYTES>");
                                continue;
                            },
                            Err(ReaderErr::UnexpectedValue) => {
                                error!("ERROR-CODE: reason <UNEXPECTED VALUE>");
                                continue;
                            },
                        };
                        error!("ERROR-CODE: err {} , reason {}", err.get_name(), reason)
                },
                ReaderAttribute::UnknownAttributes(r) => for unknown_attr_code in r.unknown_type_codes() {
                    match unknown_attr_code {
                        Some(code) => error!("UNKNOWN-ATTRIBUTE: {:#04x}", code),
                        None => error!("UNKNOWN-ATTRIBUTE: <NOT ENOUGH BYTES>"),
                    }
                },
                ReaderAttribute::Realm(r) => match r.get_value() {
                    Ok(val) => error!("REALM: {}", val),
                    Err(ReaderErr::NotEnoughBytes) => error!("REALM: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => error!("REALM: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::Nonce(r) => match r.get_value() {
                    Ok(val) => error!("NONCE: {}", val),
                    Err(ReaderErr::NotEnoughBytes) => error!("NONCE: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => error!("NONCE: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::XorMappedAddress(r) => match r.get_address() {
                    Ok(SocketAddr::V4(ip, port)) => error!("XOR-MAPPED-ADDRESS: {}", net::SocketAddr::new(net::IpAddr::from(ip.to_be_bytes()), port)),
                    Ok(SocketAddr::V6(ip, port)) => error!("XOR-MAPPED-ADDRESS: {}", net::SocketAddr::new(net::IpAddr::from(ip.to_be_bytes()), port)),
                    Err(ReaderErr::NotEnoughBytes) => error!("XOR-MAPPED-ADDRESS: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => error!("XOR-MAPPED-ADDRESS: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::Software(r) => match r.get_value() {
                    Ok(val) => error!("SOFTWARE: {}", val),
                    Err(ReaderErr::NotEnoughBytes) => error!("SOFTWARE: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => error!("SOFTWARE: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::AlternateServer(r) => match r.get_address() {
                    Ok(SocketAddr::V4(ip, port)) => error!("ALTERNATE-SERVER: {}", net::SocketAddr::new(net::IpAddr::from(ip.to_be_bytes()), port)),
                    Ok(SocketAddr::V6(ip, port)) => error!("ALTERNATE-SERVER: {}", net::SocketAddr::new(net::IpAddr::from(ip.to_be_bytes()), port)),
                    Err(ReaderErr::NotEnoughBytes) => error!("ALTERNATE-SERVER: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => error!("ALTERNATE-SERVER: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::Fingerprint(r) => match r.get_value() {
                    Some(fingerprint) => error!("FINGERPRINT: {:#08x}", fingerprint),
                    None => error!("FINGERPRINT: <NOT ENOUGH BYTES>"),
                },
                ReaderAttribute::OptionalAttribute { typ, value } => {
                    error!("OPTIONAL ATTRIBUTE: typ {:#04x} , value {:?}", typ, value)
                },
            },
            Err(ReaderErr::NotEnoughBytes) => {
                error!("Attr decoder: <NOT ENOUGH BYTES>");
            },
            Err(ReaderErr::UnexpectedValue) => {
                error!("Attr decoder: <UNEXPECTED VALUE>");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate pretty_env_logger;

    #[test]
    fn test_udp_call() {
        pretty_env_logger::init();
        use stun_proto::rfc5389::*;

        let client = Client::new(time::Duration::from_secs(1));

        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf);
        w.set_message_type(MessageType::BindingRequest);
        w.set_transaction_id(0x1020);
        let bytes_written = w.finish().unwrap() as usize;

        error!(" --- REQUEST BEGIN ---");
        print_stun_msg(&buf[0..bytes_written]);
        error!(" --- REQUEST END ---");

        let resp = client.call_addr("stun.stunprotocol.org:3478", Protocol::UDP, &mut buf, bytes_written);
        match resp {
            Ok(size) => {
                error!(" --- RESPONSE BEGIN ---");
                print_stun_msg(&buf[0..size]);
                error!(" --- RESPONSE END ---");
            },
            Err(err) => {
                error!("Could not call STUN server: {:?}", err);
            }
        }
    }

}
