use common::{Error};

pub static ID: usize = 17;

#[derive(Debug, Default)]
pub struct UDP {
    total_len: u16
}

impl UDP {
    pub fn new(ip_len: u16) -> UDP {
        let mut p_udp = UDP::default();
        p_udp.total_len = ip_len;
        p_udp
    }

    pub fn process(&mut self, data:  &[u8]) -> Result<bool, Error> {
         if data.len() < 14 {
            return Err(Error::Underflow);
        }
        
        Ok(true)
    }
    
}
