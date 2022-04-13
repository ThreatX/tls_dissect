use byteorder::{BigEndian, ReadBytesExt};
use nom::{be_u16, be_u8, IResult};
use protocol::L7Protocol;
use std::io::Cursor;
use std::str;
use tls::{TlsHandshakeType, TlsParser, TlsRecordType, TlsVersion};

#[inline]
fn is_horizontal_space(c: &u8) -> bool {
    *c == b' ' || *c == b'\t'
}

#[inline]
fn is_newline(c: &u8) -> bool {
    *c == b'\r' || *c == b'\n'
}

#[inline]
fn is_vchar(c: u8) -> bool {
    c > 32 && c <= 126
}

named!(pub be_u24<&[u8],u32>,
    map!(take!(3),|buffer: &[u8]|{
        let mut bytes = [0, 0, 0, 0];
        bytes[1] = buffer[0];
        bytes[2] = buffer[1];
        bytes[3] = buffer[2];
        let mut buf = Cursor::new(&bytes[..]);
        match buf.read_u32::<BigEndian>() {
            Ok(val) => val,
            Err(err) => {
                info!("Could not parse into u32. Returning 0. Err: {}", err);
                0
            }
        }
    })
);

#[inline]
fn match_tls<'a>(input: &'a [u8]) -> IResult<&'a [u8], L7Protocol> {
    chain!(input,
        record_type: switch!(be_u8,
            0x16 => value!(TlsRecordType::Handshake) |
            0x14 => value!(TlsRecordType::ChangeCipherSpec) |
            0x15 => value!(TlsRecordType::Alert) |
            0x17 => value!(TlsRecordType::AppData)
        )~
        _version: cond_reduce!(record_type == TlsRecordType::Handshake, switch!(be_u16,
            0x0002 => value!(TlsVersion::Ssl_2_0) |
            0x0300 => value!(TlsVersion::Ssl_3_0) |
            0x0301 => value!(TlsVersion::Tls_1_0) |
            0x0302 => value!(TlsVersion::Tls_1_1) |
            0x0303 => value!(TlsVersion::Tls_1_2) |
            0xfeff => value!(TlsVersion::Dtls_1_0) |
            0xfefd => value!(TlsVersion::Dtls_1_1)
        )) ~
        length: be_u16 ~
        handshake_type: cond_reduce!(length <= 16385, switch!(be_u8,
            0x00 => value!(TlsHandshakeType::HelloRequest) |
            0x01 => value!(TlsHandshakeType::ClientHello) |
            0x02 => value!(TlsHandshakeType::ServerHello) |
            0x03 => value!(TlsHandshakeType::HelloVerifyRequest) |
            0x04 => value!(TlsHandshakeType::NewSessionTicket) |
            0x0b => value!(TlsHandshakeType::Certificate) |
            0x0c => value!(TlsHandshakeType::ServerKeyExchange) |
            0x0d => value!(TlsHandshakeType::CertificateRequest) |
            0x0e => value!(TlsHandshakeType::ServerHelloDone) |
            0x0f => value!(TlsHandshakeType::CertificateVerify) |
            0x10 => value!(TlsHandshakeType::ClientKeyExchange) |
            0x14 => value!(TlsHandshakeType::Finished) |
            0x15 => value!(TlsHandshakeType::CertificateUrl) |
            0x16 => value!(TlsHandshakeType::CertificateStatus) |
            0x17 => value!(TlsHandshakeType::SupplementalData)
        )) ~
        hello_len: cond_reduce!(handshake_type == TlsHandshakeType::ClientHello, be_u24) ~
        hello_version: cond_reduce!(length as u32 > hello_len, switch!(be_u16,
            0x0002 => value!(TlsVersion::Ssl_2_0) |
            0x0300 => value!(TlsVersion::Ssl_3_0) |
            0x0301 => value!(TlsVersion::Tls_1_0) |
            0x0302 => value!(TlsVersion::Tls_1_1) |
            0x0303 => value!(TlsVersion::Tls_1_2) |
            0xfeff => value!(TlsVersion::Dtls_1_0) |
            0xfefd => value!(TlsVersion::Dtls_1_1)
        )) ~
        take!(32) ~ // Random
        session_len: be_u8 ~
        take!(session_len) ~ // SessionID
        cipher_len: be_u16 ~
        cond_reduce!((cipher_len as u32) < hello_len, take!(cipher_len)),
        || {
            L7Protocol::Tls(TlsParser::new(hello_version))
        }
    )
}

#[inline]
fn match_ssh<'a>(input: &'a [u8]) -> IResult<&'a [u8], L7Protocol> {
    chain!(input,
        tag!("SSH-") ~
        _version:  map_res!(take_until!("-"), str::from_utf8) ~
        take!(1) ~
        _software: map_res!(take_till!(is_newline), str::from_utf8),
        || {
            L7Protocol::SSH
        }
    )
}

pub fn detect_l7_protocol<'a>(input: &'a [u8]) -> IResult<&'a [u8], L7Protocol> {
    chain!(
        input,
        protocol:
            alt!(
                match_ssh => { |protocol| protocol } |
                match_tls => { |protocol| protocol }
            ),
        || {
            info!("Matched protocol: {:?}", protocol);
            protocol
        }
    )
}
