use protocol::L7Protocol;
use super::parsers;
use nom::IResult;

#[derive(Debug, Default)]
pub struct Detector;

impl Detector {
    pub fn detect_protocol<'a>(&'a self, payload: &'a [u8]) -> L7Protocol {
        if payload.len() == 0 {
            return L7Protocol::Unknown;
        }
        
        match parsers::detect_l7_protocol(payload) {
            IResult::Done(_i, match_result) => match_result,
            _ => L7Protocol::Unknown
        }
    }
}
