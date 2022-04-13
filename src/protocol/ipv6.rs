use common::{Error};

pub static ID: usize = 0x86dd;

#[derive(Debug, Default)]
pub struct IPv6;

impl IPv6 {
    pub fn process(&mut self, data:  &[u8]) -> Result<bool, Error> {
        if data.len() < 14 {
            return Err(Error::Underflow);
        }
        
        Ok(true)
    }
}
