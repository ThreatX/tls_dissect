use std::io;
use std::str;
use std::ffi::CStr;
use num::FromPrimitive;
use byteorder::{NetworkEndian, ReadBytesExt};
use super::Error;

#[inline]
pub fn buffer_to_uint<T>(buffer: &[u8]) -> Result<T, Error> 
    where T: FromPrimitive
{
    let buf_len = buffer.len();
    let mut rdr = io::Cursor::new(buffer);
    let result: Option<T> = match buf_len {
        1 => T::from_u8(try!(rdr.read_u8())),
        2 => T::from_u16(try!(rdr.read_u16::<NetworkEndian>())),
        4 => T::from_u32(try!(rdr.read_u32::<NetworkEndian>())),
        8 => T::from_u64(try!(rdr.read_u64::<NetworkEndian>())),
        _ => return Err(Error::ConversionError("Invalid Mac address length"))
    };
    match result {
        Some(val) => Ok(val),
        None => Err(Error::ConversionError("Error during conversion. Got result of None"))
    }
}

pub const EMPTY_STR: &'static str = "";

#[inline]
pub fn cstr_to_str<'a>(cstr: *const i8) -> &'a str {
    let slice = unsafe {
        CStr::from_ptr(cstr)
    }.to_bytes();
    match str::from_utf8(slice) {
        Ok(val) => val,
        Err(err) => {
            info!("Could not convert slice to str. Err: {}", err);
            return EMPTY_STR;
        }
    }
}

