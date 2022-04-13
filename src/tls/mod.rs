use common::conversion;
use nom::{be_u16, be_u8, IResult};
use protocol::{IPv4, TCP};
use ring;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::str;
use tracker::Direction;

pub mod matches;
pub mod parsers;

pub use tls::matches::TlsData;

#[derive(Debug, PartialEq)]
pub enum TlsRecordType {
    Handshake,
    ChangeCipherSpec,
    Alert,
    AppData,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TlsHandshakeType {
    HelloRequest,
    ClientHello,
    ServerHello,
    HelloVerifyRequest,
    NewSessionTicket,
    Certificate,
    ServerKeyExchange,
    CertificateRequest,
    ServerHelloDone,
    CertificateVerify,
    ClientKeyExchange,
    Finished,
    CertificateUrl,
    CertificateStatus,
    SupplementalData,
    Unknown,
}

#[derive(Debug, PartialEq, PartialOrd)]
#[allow(non_camel_case_types)]
pub enum TlsVersion {
    Ssl_2_0,
    Ssl_3_0,
    Tls_1_0,
    Tls_1_1,
    Tls_1_2,
    Dtls_1_0,
    Dtls_1_1,
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum TlsExtensionType {
    ServerName,
    MaxFragmentLength,
    ClientCertificateUrl,
    TrustedCaKeys,
    TruncatedHmac,
    StatusRequest,
    UserMapping,
    ClientAuthz,
    ServerAuthz,
    CertType,
    SupportedGroups,
    EcPointFormats,
    Srp,
    SignatureAlgorithms,
    UseSrtp,
    Heartbeat,
    ApplicationLayerProtocolNegotiation,
    StatusRequestV2,
    SignedCertificateTimestamp,
    ClientCertificateType,
    ServerCertificateType,
    Padding,
    EncryptThenMac,
    ExtendedMasterSecret,
    TokenBinding,
    CachedInfo,
    SessionTicketTls,
    NextProtocolNegotiation,
    RenegotiationInfo,
    Unknown,
}

#[derive(Debug, PartialEq, Clone)]
#[allow(non_camel_case_types)]
pub enum KexType {
    Unknown,
    RSA,
    DHE,
    ECDHE,
}

#[derive(Debug, PartialEq, Clone)]
pub enum EcCurveType {
    Unknown,
    ExplicitPrime,
    ExplicitChar,
    NamedCurve,
}

#[derive(Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum CipherType {
    Null,
    ARC2,
    ARC4,
    DES,
    DES3,
    AES,
}

#[derive(Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum HashType {
    Null,
    MD5,
    SHA,
    SHA256,
    SHA384,
}

#[derive(Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum CipherMode {
    Null,
    CBC,
    GCM,
}

#[derive(Debug, PartialEq, Clone)]
#[allow(non_camel_case_types)]
pub enum SigType {
    Null,
    RSA,
    DSA,
    ECDSA,
}

#[derive(Debug)]
pub struct Cipher {
    pub name: &'static str,
    pub kex: KexType,
    pub kex_sig: SigType,
    pub cipher: CipherType,
    pub key_len: u16,
    pub mode: CipherMode,
    pub hash: HashType,
}

lazy_static! {
    pub static ref CIPHERS: HashMap<u16, Cipher> = {
        let mut map: HashMap<u16, Cipher> = HashMap::with_capacity(20);
        map.insert(
            0x0028,
            Cipher {
                name: "ECDHE_RSA_WITH_AES_256_CBC_SHA384",
                kex: KexType::ECDHE,
                kex_sig: SigType::RSA,
                cipher: CipherType::AES,
                key_len: 16,
                mode: CipherMode::CBC,
                hash: HashType::SHA384,
            },
        );
        map.insert(
            0xc014,
            Cipher {
                name: "ECDHE_RSA_WITH_AES_256_CBC_SHA",
                kex: KexType::ECDHE,
                kex_sig: SigType::RSA,
                cipher: CipherType::AES,
                key_len: 32,
                mode: CipherMode::CBC,
                hash: HashType::SHA,
            },
        );
        map.insert(
            0xc028,
            Cipher {
                name: "ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                kex: KexType::ECDHE,
                kex_sig: SigType::RSA,
                cipher: CipherType::AES,
                key_len: 32,
                mode: CipherMode::GCM,
                hash: HashType::SHA384,
            },
        );
        map
    };
}

#[derive(Debug)]
pub struct Extension<'a> {
    data: &'a [u8],
}

#[derive(Debug)]
pub struct ClientHello<'a> {
    tls_version: TlsVersion,
    session_id: &'a [u8],
    extensions: Option<HashMap<TlsExtensionType, Extension<'a>>>,
}

impl<'a> ClientHello<'a> {
    fn ext_server_name(&self) -> Option<&str> {
        if let Some(ref extensions) = self.extensions {
            if let Some(sni) = extensions.get(&TlsExtensionType::ServerName) {
                let length = match conversion::buffer_to_uint::<u16>(&sni.data[0..2]) {
                    Ok(val) => val,
                    Err(err) => {
                        warn!(
                            "Could not convert to u16. Returning None. Buffer: {:?}, Err: {}",
                            sni.data, err
                        );
                        return None;
                    }
                };
                println!("Len: {:?}\n\n", length);
                let name_type = sni.data[2];
                if name_type != 0 {
                    warn!("Unrecognized SNI name_type: {}", name_type);
                    return None;
                }

                let name_length = match conversion::buffer_to_uint::<u16>(&sni.data[3..5]) {
                    Ok(val) => val,
                    Err(err) => {
                        warn!(
                            "Could not convert to u16. Returning None. Buffer: {:?}, Err: {}",
                            sni.data, err
                        );
                        return None;
                    }
                };
                let end_pos = 5 + name_length as usize;
                let name = match str::from_utf8(&sni.data[5..end_pos]) {
                    Ok(val) => val,
                    Err(err) => {
                        warn!("Could not convert from utf8. Returning None. Err: {}", err);
                        return None;
                    }
                };
                println!("Server name: {:?}\n\n", name);
                return Some(name);
            }
        }
        None
    }
}

#[derive(Debug)]
pub struct ServerHello<'a> {
    tls_version: TlsVersion,
    session_id: &'a [u8],
    cipher_suite: u16,
    compression_method: u8,
    extensions: Option<HashMap<TlsExtensionType, Extension<'a>>>,
}

#[derive(Debug)]
pub struct ClientKeyExchange<'a> {
    kex_type: KexType,
    sig_type: SigType,
    data: &'a [u8],
}

#[derive(Debug)]
pub struct Certificate<'a> {
    cert: &'a [u8],
}

pub enum KexParams<'a> {
    EcdheParams(EcdheParams<'a>),
    Unimplemented,
}

pub struct EcdheParams<'a> {
    algo: &'a ring::agreement::Algorithm,
    pubkey: &'a [u8],
}

pub struct ServerKeyExchange<'a> {
    params: KexParams<'a>,
}

impl<'a> fmt::Debug for ServerKeyExchange<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ServerKeyExchange found")
    }
}

#[derive(Debug)]
pub enum ParserResult<'a> {
    ClientHello(ClientHello<'a>),
    ServerHello(ServerHello<'a>),
    ServerKeyExchange(ServerKeyExchange<'a>),
    ClientKeyExchange(ClientKeyExchange<'a>),
    Certificate(Certificate<'a>),
    Unimplemented,
}

impl<'a> ParserResult<'a> {
    pub fn name(&self) -> &str {
        match *self {
            ParserResult::ClientHello(_) => "ClientHello",
            ParserResult::ServerHello(_) => "ServerHello",
            ParserResult::ServerKeyExchange(_) => "ServerKeyExchange",
            ParserResult::ClientKeyExchange(_) => "ClientKeyExchange",
            ParserResult::Certificate(_) => "Certificate",
            _ => {
                warn!("Method 'name' not implemented for: {:?}", &self);
                ""
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct TlsParser {
    version: TlsVersion,
    sni: String,
    crypto: u16,
}

impl TlsParser {
    pub fn new(version: TlsVersion) -> TlsParser {
        println!("Detected Tls version: {:?}", version);
        TlsParser {
            version: version,
            sni: String::new(),
            crypto: 0x00,
        }
    }
    pub fn process(&mut self, direction: Direction, ipv4: &IPv4, tcp: &TCP) -> bool {
        if let IResult::Done(_, results) = parsers::tls_packet(tcp.payload.as_slice(), self.crypto)
        {
            for result in results {
                let tls_data = TlsData {
                    ip: match ipv4.ip_src {
                        IpAddr::V4(val) => u32::from(val),
                        IpAddr::V6(_) => {
                            warn!("IPv6 not yet supported!");
                            0
                        }
                    },
                    raw_request: &tcp.payload,
                    packet: Some(result),
                };
                if let Some(p) = tls_data.packet {
                    if let ParserResult::ClientHello(ch) = p {
                        println!("ClientHello: {:?}", ch.ext_server_name());
                    }
                }
            }
        }
        true
    }
}
