pub mod ethernet;
pub mod ip;
pub mod ipv6;
pub mod tcp;
pub mod udp;

use common::Error;
pub use protocol::ethernet::Ethernet;
pub use protocol::ip::IPv4;
pub use protocol::ipv6::IPv6;
pub use protocol::tcp::TCP;
pub use protocol::udp::UDP;
use tls::TlsParser;
use tracker::Direction;

#[derive(Debug)]
pub enum Protocol {
    Ethernet(Ethernet),
    IPv4(IPv4),
    IPv6(IPv6),
    TCP(TCP),
    UDP(UDP),
    Unknown,
}

impl Protocol {
    pub fn id(&self) -> usize {
        match *self {
            Protocol::Ethernet(_) => ethernet::ID,
            Protocol::IPv4(_) => ip::ID,
            Protocol::IPv6(_) => ipv6::ID,
            Protocol::TCP(_) => tcp::ID,
            Protocol::UDP(_) => udp::ID,
            _ => 0,
        }
    }

    fn process(&mut self, data: &[u8]) -> Result<bool, Error> {
        match *self {
            Protocol::Ethernet(ref mut val) => val.process(data),
            Protocol::IPv4(ref mut val) => val.process(data),
            Protocol::IPv6(ref mut val) => val.process(data),
            Protocol::TCP(ref mut val) => val.process(data),
            Protocol::UDP(ref mut val) => val.process(data),
            _ => Ok(true),
        }
    }
}

#[derive(Debug)]
pub enum L7Protocol {
    // HTTP(HttpParser),
    Tls(TlsParser),
    SSH,
    FTP,
    SMTP,
    Unknown,
}

impl Default for L7Protocol {
    fn default() -> L7Protocol {
        L7Protocol::Unknown
    }
}

impl L7Protocol {
    pub fn process(&mut self, direction: Direction, ipv4: &IPv4, tcp: &TCP) -> bool {
        match *self {
            L7Protocol::Tls(ref mut val) => val.process(direction, ipv4, tcp),
            _ => {
                info!("Check not implemented for protocol: {:?}", self);
                false
            }
        }
    }
}
