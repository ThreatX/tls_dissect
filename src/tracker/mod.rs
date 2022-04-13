use std::net::IpAddr;
use std::collections::HashMap;
use protocol::{Protocol, IPv4, TCP, L7Protocol};

pub mod detector;
pub mod parsers;

use tracker::detector::Detector;
use common::net;

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Session {
    src_ip: IpAddr,
    dst_ip: IpAddr,
    src_port: u16,
    dst_port: u16
}

#[derive(Debug, PartialEq)]
pub enum Direction {
    C2S,
    S2C,
    Unknown
}

static TH_FIN: u8 =  0x01;
static TH_SYN: u8 = 0x02;
static TH_RST: u8 =  0x04;
// static TH_PUSH: u8 = 0x08;
static TH_ACK: u8 = 0x10;
// static TH_URG: u8 = 0x20;
// static TH_ECE: u8 = 0x40;
// static TH_CWR: u8 =  0x80;


pub struct Tracker {
    sessions: HashMap<Session, L7Protocol>, // <src_ip <dst_ip, session>>
    _local_ips: Vec<IpAddr>,
    detector: detector::Detector
}

impl Tracker {
    pub fn new() -> Tracker {
        let local_ips = match net::get_local_ips() {
            Some(val) => val,
            None => Vec::with_capacity(10)
        };

        Tracker {
            sessions: HashMap::new(),
            _local_ips: local_ips,
            detector: Detector::default()
        }
    }

    pub fn consume(&mut self, protocol: &Box<Protocol>) -> bool {
        match **protocol {
            Protocol::Ethernet(ref val) => self.consume(&val.l3_protocol),
            Protocol::IPv4(ref val) => self.parse_ipv4(val),
            _ => true

        }
    }

    fn parse_ipv4(&mut self, ipv4: &IPv4) -> bool {
        match *ipv4.l4_protocol {
            Protocol::TCP(ref val) => self.parse_tcp(ipv4, val),
            _ => true
        }
    }

    fn parse_tcp(&mut self, ipv4: &IPv4, tcp: &TCP) -> bool {
        let ip_src = ipv4.ip_src;
        let ip_dst = ipv4.ip_dst;
        let flags = tcp.flags;

        let c2s_session = Session {
            src_ip: ip_src,
            dst_ip: ip_dst,
            src_port: tcp.s_port,
            dst_port: tcp.d_port
        };
        let s2c_session = Session {
            src_ip: ip_dst,
            dst_ip: ip_src,
            src_port: tcp.d_port,
            dst_port: tcp.s_port
        };

        // Terminate session
        if (flags & TH_FIN) > 0 || (flags & TH_RST) > 0 {
            if self.sessions.contains_key(&c2s_session) {
                info!("FIN or RST packet on src_ip: {:?}, flags: {}", ip_src, flags);
                self.sessions.remove(&c2s_session);
            }
            else if self.sessions.contains_key(&s2c_session) {
                info!("FIN or RST packet on src_ip: {:?}, flags: {}", ip_dst, flags);
                self.sessions.remove(&s2c_session);
            }
        }
        // New session
        else if (flags & TH_SYN) > 0 && (flags & TH_ACK) == 0{
            // Create new session
            info!("SYN packet on src_ip: {:?}, flags: {}", ip_src, flags);
            self.sessions.insert(c2s_session, L7Protocol::Unknown);
        }
        // No further action on 0 length packets
        else if tcp.payload.len() == 0 {
            return true;
        }
        // C2S communication
        else if self.sessions.contains_key(&c2s_session) {
            if let Some(l7_protocol) = self.sessions.get_mut(&c2s_session) {
                // If protocol not known attempt to detect
                if let L7Protocol::Unknown = *l7_protocol {
                    let result = self.detector.detect_protocol(&tcp.payload);
                    *l7_protocol = result;
                }
                l7_protocol.process(Direction::C2S, ipv4, tcp);
            }
        }
        // S2C communication
        else if self.sessions.contains_key(&s2c_session) {
            if let Some(l7_protocol) = self.sessions.get_mut(&s2c_session) {
                if let L7Protocol::Unknown = *l7_protocol {
                    let result = self.detector.detect_protocol(&tcp.payload);
                    *l7_protocol = result;
                }
                l7_protocol.process(Direction::S2C, ipv4, tcp);
            }
        }

        true
    }

}
