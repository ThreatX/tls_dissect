use common::{conversion, Error};

pub static ID: usize = 6;

#[derive(Debug, Default)]
pub struct TCP {
    total_len: u16,
    pub s_port: u16,
    pub d_port: u16,
    pub seq_nr: u32,
    pub ack_nr: u32,
    pub data_off: u8,
    pub flags: u8,
    pub window: u16,
    pub sum: u16,
    pub urp: u16,
    pub payload: Vec<u8>
}

impl TCP {
    pub fn new(ip_len: u16) -> TCP {
        let mut p_tcp = TCP::default();
        p_tcp.total_len = ip_len;
        p_tcp
    }

}

impl TCP {
    pub fn process(&mut self, data:  &[u8]) -> Result<bool, Error> {
        self.s_port = try!(conversion::buffer_to_uint::<u16>(&data[0..2]));
        self.d_port = try!(conversion::buffer_to_uint::<u16>(&data[2..4]));
        self.seq_nr = try!(conversion::buffer_to_uint::<u32>(&data[4..8]));
        self.ack_nr = try!(conversion::buffer_to_uint::<u32>(&data[8..12]));
        self.data_off = (data[12] & 0xf0) >> 4;
        self.flags = data[13];
        self.window = try!(conversion::buffer_to_uint::<u16>(&data[14..16]));
        self.sum = try!(conversion::buffer_to_uint::<u16>(&data[16..18]));
        self.urp = try!(conversion::buffer_to_uint::<u16>(&data[18..20]));

        let offset = (self.data_off as usize) * 4;
        let packet_len = self.total_len as usize - offset;

//         if packet_len > 2048 {
//             return Ok(true);
//         }

        info!("Packet len: {}", packet_len);
        self.payload = Vec::from(&data[offset..(offset + packet_len)]);

        Ok(true)
    }
}
