use std::fmt;
use super::{Protocol, IPv4, IPv6};
use common::{conversion, Error};

pub static ID: usize = 0x8032;

pub struct Ethernet {
    pub ether_dhost: Vec<u8>,
    pub ether_shost: Vec<u8>,
    pub ether_type: u16,
    pub l3_protocol: Box<Protocol>
}

impl Default for Ethernet {
    fn default() -> Ethernet {
        Ethernet {
            ether_dhost: Vec::new(),
            ether_shost: Vec::new(),
            ether_type: 0,
            l3_protocol: Box::new(Protocol::Unknown)
        }
    }
}

impl fmt::Debug for Ethernet {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "
Ethernet {{ 
    ether_dhost: {:?}, 
    ether_shost: {:?},
    ether_type: {}
}}", self.ether_dhost, self.ether_shost, self.ether_type)
    }
}

impl Ethernet {
    pub fn mac_address(v_addr: &Vec<u8>) -> Result<String, Error> {
        if v_addr.len() != 6 {
            return Err(Error::InvalidFormat("Invalid Mac address length"));
        }

        let encoded = v_addr.iter().fold(String::new(), |mut acc, x| {
            if acc.len() > 0 {
                acc.push_str(&format!(":{:02x}", x));
            }
            else {
                acc.push_str(&format!("{:02x}", x));
            }
            acc
        });

        Ok(encoded)
    }
    
    pub fn process(&mut self, data:  &[u8]) -> Result<bool, Error> {
         if data.len() < 14 {
            return Err(Error::Underflow);
        }
        
        let dhost = Vec::from(&data[0..6]);
        self.ether_dhost = dhost;
        let shost = Vec::from(&data[6..12]);
        self.ether_shost = shost;
        let ether_type = match conversion::buffer_to_uint::<u16>(&data[12..14]) {
            Ok(val) => val,
            Err(err) => panic!("Err: {}", err)
        };
        self.ether_type = ether_type;
        
        let packet = &data[14..];
        
        let mut l3_protocol: Protocol = match ether_type {
            0x800 => Protocol::IPv4(IPv4::default()),
            0x86dd => Protocol::IPv6(IPv6),
            _ => Protocol::Unknown
        };
        
        let result = l3_protocol.process(packet);
        if let Ok(is_success) = result {
            if is_success {
                self.l3_protocol = Box::new(l3_protocol);
            }
        }
        result
    }
}
