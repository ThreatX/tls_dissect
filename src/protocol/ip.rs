use super::{Protocol, TCP, UDP};
use common::{conversion, Error};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

pub static ID: usize = 0x800;

pub struct IPv4 {
    pub version: u8,
    pub header_len: u16,
    pub ip_tos: u8,
    pub ip_len: u16,
    pub ip_id: u16,
    pub ip_off: u16,
    pub ip_ttl: u8,
    pub ip_p: u8,
    pub ip_sum: u16,
    pub ip_src: IpAddr,
    pub ip_dst: IpAddr,
    pub l4_protocol: Box<Protocol>,
}

impl Default for IPv4 {
    fn default() -> IPv4 {
        IPv4 {
            version: 0,
            header_len: 0,
            ip_tos: 0,
            ip_len: 0,
            ip_id: 0,
            ip_off: 0,
            ip_ttl: 0,
            ip_p: 0,
            ip_sum: 0,
            ip_src: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            ip_dst: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            l4_protocol: Box::new(Protocol::Unknown),
        }
    }
}

impl fmt::Debug for IPv4 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "
IPv4 {{
    version: {},
    header_len: {},
    ip_tos: {},
    ip_len: {},
    ip_id: {},
    ip_off: {},
    ip_ttl: {},
    ip_p: {},
    ip_sum: {},
    ip_src: {:?},
    ip_dst: {:?}
}}",
            self.version,
            self.header_len,
            self.ip_tos,
            self.ip_len,
            self.ip_id,
            self.ip_off,
            self.ip_ttl,
            self.ip_p,
            self.ip_sum,
            self.ip_src,
            self.ip_dst
        )
    }
}

impl IPv4 {
    pub fn process(&mut self, data: &[u8]) -> Result<bool, Error> {
        if data.len() < 20 {
            return Err(Error::Underflow);
        }

        self.version = data[0] >> 4;
        self.header_len = (data[0] & 0x0f) as u16 * 4;
        self.ip_tos = data[1];
        self.ip_len = conversion::buffer_to_uint::<u16>(&data[2..4])?;
        self.ip_id = conversion::buffer_to_uint::<u16>(&data[4..6])?;
        self.ip_off = conversion::buffer_to_uint::<u16>(&data[6..8])?;
        self.ip_ttl = data[8];
        self.ip_p = data[9];
        self.ip_sum = conversion::buffer_to_uint::<u16>(&data[10..12])?;
        self.ip_src = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
        self.ip_dst = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

        let mut l4_protocol: Protocol = match self.ip_p {
            6 => Protocol::TCP(TCP::new(self.ip_len - self.header_len as u16)),
            17 => Protocol::UDP(UDP::new(self.ip_len - self.header_len as u16)),
            _ => Protocol::Unknown,
        };

        let packet = &data[20..];
        let result = l4_protocol.process(packet);
        if let Ok(is_success) = result {
            if is_success {
                self.l4_protocol = Box::new(l4_protocol);
            }
        }
        result
    }
}
