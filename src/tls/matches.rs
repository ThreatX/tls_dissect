use super::ParserResult;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

lazy_static! {
    static ref EMPTY_VEC: Vec<u8> = Vec::new();
}

#[derive(Debug)]
pub struct TlsData<'a> {
    pub ip: u32,
    pub raw_request: &'a Vec<u8>,
    pub packet: Option<ParserResult<'a>>,
}

impl<'a> TlsData<'a> {
    pub fn new() -> TlsData<'a> {
        TlsData {
            ip: 0,
            raw_request: &EMPTY_VEC,
            packet: None,
        }
    }
}

// Being matches
