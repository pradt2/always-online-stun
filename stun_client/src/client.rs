use std::*;
use std::io::{Read, Write};
use log::debug;

pub enum Protocol {
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
                debug!("{:?}", sock.peer_addr());
                sock.send(buf)
            }
            ConnRef::TCP(stream) => {
                stream.set_write_timeout(Some(timeout))?;
                stream.write(buf)
            }
        }
    }
}

pub struct Client {
    timeout: time::Duration,
}

impl Client {
    pub fn new(timeout: time::Duration) -> Self {
        Self {
            timeout
        }
    }

    pub fn call_addr<T: net::ToSocketAddrs>(&self, remote_addr: T, proto: Protocol, buf: &mut [u8], msg_size: usize) -> io::Result<usize> {
        let mut conn = Conn::connect("0.0.0.0:0", remote_addr, proto, self.timeout)?;
        self.call_conn(&mut conn, buf, msg_size)
    }

    pub fn call_conn<'a, T: Into<ConnRef<'a>>>(&self, conn: T, buf: &mut [u8], msg_size: usize) -> io::Result<usize> {
        let mut conn = conn.into();
        let mut bytes_written = 0;
        while bytes_written < msg_size {
            bytes_written += conn.write(&mut buf[bytes_written..msg_size], self.timeout)?;
        };
        conn.read(buf, self.timeout)
    }
}

pub fn print_stun_msg(buf: &[u8]) {
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
    debug!("Type: {}", message_type_to_str(reader.get_message_type()));
    debug!("Len: {}", match reader.get_message_length() { Some(len) => len.to_string(), None => String::from("<NOT ENOUGH BYTES>") });
    debug!("Cookie: {}", match reader.get_magic_cookie() { Some(cookie) => format!("{:#01X}", cookie), None => String::from("<NOT ENOUGH BYTES>") });
    debug!("Transaction ID: {}", match reader.get_transaction_id() { Some(tid) => format!("{:#01X}", tid), None => String::from("<NOT ENOUGH BYTES>") });

    for attr in reader.get_attributes() {
        match attr {
            Ok(reader) => match reader {
                ReaderAttribute::MappedAddress(r) => match r.get_address() {
                    Ok(SocketAddr::V4(ip, port)) => debug!("MAPPED-ADDRESS: {}", net::SocketAddr::new(net::IpAddr::from(ip.to_be_bytes()), port)),
                    Ok(SocketAddr::V6(ip, port)) => debug!("MAPPED-ADDRESS: {}", net::SocketAddr::new(net::IpAddr::from(ip.to_be_bytes()), port)),
                    Err(ReaderErr::NotEnoughBytes) => debug!("MAPPED-ADDRESS: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => debug!("MAPPED-ADDRESS: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::Username(r) => match r.get_value() {
                    Ok(val) => debug!("USERNAME: {}", val),
                    Err(ReaderErr::NotEnoughBytes) => debug!("USERNAME: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => debug!("USERNAME: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::MessageIntegrity(r) => match r.get_value() {
                    Some(val) => debug!("MESSAGE-INTEGRITY: {:?}", val),
                    None => debug!("MESSAGE-INTEGRITY: <NOT ENOUGH BYTES>"),
                },
                ReaderAttribute::ErrorCode(r) => {
                    let err = match r.get_error() {
                        Ok(code) => code,
                        Err(ReaderErr::NotEnoughBytes) => {
                            debug!("ERROR-CODE: err <NOT ENOUGH BYTES>");
                            continue;
                        },
                        Err(ReaderErr::UnexpectedValue) => {
                            debug!("ERROR-CODE: err <UNEXPECTED VALUE>");
                            continue;
                        },
                    };
                    let reason = match r.get_reason() {
                        Ok(reason) => reason,
                        Err(ReaderErr::NotEnoughBytes) => {
                            debug!("ERROR-CODE: reason <NOT ENOUGH BYTES>");
                            continue;
                        },
                        Err(ReaderErr::UnexpectedValue) => {
                            debug!("ERROR-CODE: reason <UNEXPECTED VALUE>");
                            continue;
                        },
                    };
                    debug!("ERROR-CODE: err {} , reason {}", err.get_name(), reason)
                },
                ReaderAttribute::UnknownAttributes(r) => for unknown_attr_code in r.unknown_type_codes() {
                    match unknown_attr_code {
                        Some(code) => debug!("UNKNOWN-ATTRIBUTE: {:#04X}", code),
                        None => debug!("UNKNOWN-ATTRIBUTE: <NOT ENOUGH BYTES>"),
                    }
                },
                ReaderAttribute::Realm(r) => match r.get_value() {
                    Ok(val) => debug!("REALM: {}", val),
                    Err(ReaderErr::NotEnoughBytes) => debug!("REALM: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => debug!("REALM: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::Nonce(r) => match r.get_value() {
                    Ok(val) => debug!("NONCE: {}", val),
                    Err(ReaderErr::NotEnoughBytes) => debug!("NONCE: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => debug!("NONCE: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::XorMappedAddress(r) => match r.get_address() {
                    Ok(SocketAddr::V4(ip, port)) => debug!("XOR-MAPPED-ADDRESS: {}", net::SocketAddr::new(net::IpAddr::from(ip.to_be_bytes()), port)),
                    Ok(SocketAddr::V6(ip, port)) => debug!("XOR-MAPPED-ADDRESS: {}", net::SocketAddr::new(net::IpAddr::from(ip.to_be_bytes()), port)),
                    Err(ReaderErr::NotEnoughBytes) => debug!("XOR-MAPPED-ADDRESS: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => debug!("XOR-MAPPED-ADDRESS: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::Software(r) => match r.get_value() {
                    Ok(val) => debug!("SOFTWARE: {}", val),
                    Err(ReaderErr::NotEnoughBytes) => debug!("SOFTWARE: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => debug!("SOFTWARE: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::AlternateServer(r) => match r.get_address() {
                    Ok(SocketAddr::V4(ip, port)) => debug!("ALTERNATE-SERVER: {}", net::SocketAddr::new(net::IpAddr::from(ip.to_be_bytes()), port)),
                    Ok(SocketAddr::V6(ip, port)) => debug!("ALTERNATE-SERVER: {}", net::SocketAddr::new(net::IpAddr::from(ip.to_be_bytes()), port)),
                    Err(ReaderErr::NotEnoughBytes) => debug!("ALTERNATE-SERVER: <NOT ENOUGH BYTES>"),
                    Err(ReaderErr::UnexpectedValue) => debug!("ALTERNATE-SERVER: <UNEXPECTED VALUE>"),
                },
                ReaderAttribute::Fingerprint(r) => match r.get_value() {
                    Some(fingerprint) => debug!("FINGERPRINT: {:#08X}", fingerprint),
                    None => debug!("FINGERPRINT: <NOT ENOUGH BYTES>"),
                },
                ReaderAttribute::OptionalAttribute { typ, value } => {
                    debug!("OPTIONAL ATTRIBUTE: typ {:#04X} , val {:?}", typ, value)
                },
            },
            Err(ReaderErr::NotEnoughBytes) => {
                debug!("Attr decoder: <NOT ENOUGH BYTES>");
            },
            Err(ReaderErr::UnexpectedValue) => {
                debug!("Attr decoder: <UNEXPECTED VALUE>");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use super::*;
    extern crate pretty_env_logger;

    #[test]
    fn test_new_client() {
        let msg = [
            0x00, 0x01,
            0x00, 0x00,
            0x21, 0x12, 0xA4, 0x42,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ];

        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.connect("stun.meetwife.com:3478").unwrap();
        sock.send(&msg).unwrap();

        let mut buf = [0u8; 128];
        let size = sock.recv(buf.as_mut()).unwrap();

        let msg = stun_proto::byte::Msg::from(buf.as_slice());
        println!("{:?}", msg);
    }

    #[test]
    fn test_udp_call() {
        use stun_proto::rfc5389::*;

        env::set_var("RUST_LOG", "debug");
        pretty_env_logger::init();

        let client = Client::new(time::Duration::from_secs(1));

        let mut buf = [0u8; 256];
        let mut w = Writer::new(&mut buf);
        w.set_message_type(MessageType::BindingRequest);
        w.set_transaction_id(0x1020);
        let bytes_written = w.finish().unwrap() as usize;

        debug!("--- REQUEST BEGIN ---");
        print_stun_msg(&buf[0..bytes_written]);
        debug!("--- REQUEST END ---");

        let resp = client.call_addr("stun3.l.google.com:19305", Protocol::UDP, &mut buf, bytes_written);
        match resp {
            Ok(size) => {
                debug!("--- RESPONSE BEGIN ---");
                print_stun_msg(&buf[0..size]);
                debug!("--- RESPONSE END ---");
            },
            Err(err) => {
                debug!("Could not call STUN server: {:?}", err);
            }
        }
    }

}
