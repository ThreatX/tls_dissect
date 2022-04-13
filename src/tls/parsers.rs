use super::*;
use nom::{be_u16, be_u32, be_u8, IResult};
use ring;
use std::collections::HashMap;
use tracker::parsers::be_u24;

pub fn tls_packet<'a>(input: &'a [u8], cipher_suite: u16) -> IResult<&'a [u8], Vec<ParserResult>> {
    let mut map: Vec<ParserResult> = Vec::new();
    let mut cipher_suite = cipher_suite;
    let result: IResult<&[u8], Vec<bool>> = many1!(
        input,
        chain!(
            record_type: switch!(be_u8,
                0x16 => value!(TlsRecordType::Handshake) |
                0x14 => value!(TlsRecordType::ChangeCipherSpec) |
                0x15 => value!(TlsRecordType::Alert) |
                0x17 => value!(TlsRecordType::AppData)
            ) ~
            version: cond_reduce!(record_type == TlsRecordType::Handshake, switch!(be_u16,
                0x0002 => value!(TlsVersion::Ssl_2_0) |
                0x0300 => value!(TlsVersion::Ssl_3_0) |
                0x0301 => value!(TlsVersion::Tls_1_0) |
                0x0302 => value!(TlsVersion::Tls_1_1) |
                0x0303 => value!(TlsVersion::Tls_1_2) |
                0xfeff => value!(TlsVersion::Dtls_1_0) |
                0xfefd => value!(TlsVersion::Dtls_1_1)
            )) ~
            length: be_u16 ~
            result: cond_reduce!(length <= 16385 && version > TlsVersion::Ssl_3_0, switch!(value!(record_type),
                TlsRecordType::Handshake => call!(tls_handshake, cipher_suite)
            )),
            || {

                if let ParserResult::ServerHello(ref val) = result {
                    cipher_suite = val.cipher_suite.clone();
                }
                map.push(result);
                true

            }
        )
    );
    let leftover = match result {
        IResult::Done(leftover, _) => leftover,
        _ => &[],
    };
    IResult::Done(leftover, map)
}

#[inline]
fn tls_handshake<'a>(input: &'a [u8], cipher_suite: u16) -> IResult<&'a [u8], ParserResult> {
    chain!(input,
        handshake_type: switch!(be_u8,
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
        ) ~
        length: be_u24 ~
        result: switch!(value!(handshake_type.clone()),
            TlsHandshakeType::HelloRequest => call!(tls_handshake_unimplemented, length) |
            TlsHandshakeType::ClientHello => call!(tls_client_hello, length) |
            TlsHandshakeType::ServerHello => call!(tls_server_hello, length) |
            TlsHandshakeType::HelloVerifyRequest => call!(tls_handshake_unimplemented, length) |
            TlsHandshakeType::NewSessionTicket => call!(tls_handshake_unimplemented, length) |
            TlsHandshakeType::Certificate => call!(tls_certificate, length) |
            TlsHandshakeType::ServerKeyExchange => call!(tls_server_key_exchange, length, cipher_suite) |
            TlsHandshakeType::CertificateRequest => call!(tls_handshake_unimplemented, length) |
            TlsHandshakeType::ServerHelloDone => call!(tls_handshake_unimplemented, length) |
            TlsHandshakeType::CertificateVerify => call!(tls_handshake_unimplemented, length) |
            TlsHandshakeType::ClientKeyExchange => call!(tls_client_key_exchange, length, cipher_suite) |
            TlsHandshakeType::Finished => call!(tls_handshake_unimplemented, length) |
            TlsHandshakeType::CertificateUrl => call!(tls_handshake_unimplemented, length) |
            TlsHandshakeType::CertificateStatus => call!(tls_handshake_unimplemented, length) |
            TlsHandshakeType::SupplementalData  => call!(tls_handshake_unimplemented, length)

        ),
        || {
            println!("Detected: {:?}", handshake_type);
            result
        }
    )
}

#[inline]
fn tls_handshake_unimplemented<'a>(
    input: &'a [u8],
    length: u32,
) -> IResult<&'a [u8], ParserResult> {
    chain!(input, take!(length), || { ParserResult::Unimplemented })
}

#[inline]
fn tls_extensions<'a>(
    input: &'a [u8],
    o_length: Option<u16>,
) -> IResult<&'a [u8], Option<HashMap<TlsExtensionType, Extension>>> {
    let mut length = match o_length {
        Some(val) => val,
        None => return IResult::Done(input, None),
    };

    let mut map: HashMap<TlsExtensionType, Extension> = HashMap::with_capacity(10);
    let result: IResult<&[u8], Vec<bool>> = many1!(
        input,
        chain!(
        ext_type: cond_reduce!(length > 0, switch!(be_u16,
            0 => value!(TlsExtensionType::ServerName) |
            1 => value!(TlsExtensionType::MaxFragmentLength) |
            2 => value!(TlsExtensionType::ClientCertificateUrl) |
            3 => value!(TlsExtensionType::TrustedCaKeys) |
            4 => value!(TlsExtensionType::TruncatedHmac) |
            5 => value!(TlsExtensionType::StatusRequest) |
            6 => value!(TlsExtensionType::UserMapping) |
            7 => value!(TlsExtensionType::ClientAuthz) |
            8 => value!(TlsExtensionType::ServerAuthz) |
            9 => value!(TlsExtensionType::CertType) |
            10 => value!(TlsExtensionType::SupportedGroups) |
            11 => value!(TlsExtensionType::EcPointFormats) |
            12 => value!(TlsExtensionType::Srp) |
            13 => value!(TlsExtensionType::SignatureAlgorithms) |
            14 => value!(TlsExtensionType::UseSrtp) |
            15 => value!(TlsExtensionType::Heartbeat) |
            16 => value!(TlsExtensionType::ApplicationLayerProtocolNegotiation) |
            17 => value!(TlsExtensionType::StatusRequestV2) |
            18 => value!(TlsExtensionType::SignedCertificateTimestamp) |
            19 => value!(TlsExtensionType::ClientCertificateType) |
            20 => value!(TlsExtensionType::ServerCertificateType) |
            21 => value!(TlsExtensionType::Padding) |
            22 => value!(TlsExtensionType::EncryptThenMac) |
            23 => value!(TlsExtensionType::ExtendedMasterSecret) |
            24 => value!(TlsExtensionType::TokenBinding) |
            25 => value!(TlsExtensionType::CachedInfo) |
            35 => value!(TlsExtensionType::SessionTicketTls) |
            13172 => value!(TlsExtensionType::NextProtocolNegotiation) |
            65281 => value!(TlsExtensionType::RenegotiationInfo) |
            26 ... 0xffff => value!(TlsExtensionType::Unknown)
        )) ~
        ext_length: be_u16 ~
        data: take!(ext_length),
        || {
            println!("Extension type: {:?}", ext_type);
            if ext_type != TlsExtensionType::Unknown {
                let ext = Extension {
                    data: data
                };
                map.insert(ext_type, ext);
            }
            length -= ext_length + 4;
            true
        })
    );
    let leftover = match result {
        IResult::Done(leftover, _) => leftover,
        _ => &[],
    };

    if map.len() == 0 {
        IResult::Done(leftover, None)
    } else {
        IResult::Done(leftover, Some(map))
    }
}

#[inline]
fn tls_client_hello<'a>(input: &'a [u8], length: u32) -> IResult<&'a [u8], ParserResult> {
    chain!(input,
        version: switch!(be_u16,
            0x0002 => value!(TlsVersion::Ssl_2_0) |
            0x0300 => value!(TlsVersion::Ssl_3_0) |
            0x0301 => value!(TlsVersion::Tls_1_0) |
            0x0302 => value!(TlsVersion::Tls_1_1) |
            0x0303 => value!(TlsVersion::Tls_1_2) |
            0xfeff => value!(TlsVersion::Dtls_1_0) |
            0xfefd => value!(TlsVersion::Dtls_1_1)
        ) ~
        take!(32) ~ // Random
        session_len: be_u8 ~
        session_id: take!(session_len) ~ // SessionID
        cipher_len: be_u16 ~
        cond_reduce!((cipher_len as u32) < length, take!(cipher_len)) ~
        compression_len: be_u8 ~
        _compression_methods: cond_reduce!((compression_len as u32) < length, take!(compression_len)) ~
        extensions_len: opt!(be_u16) ~
        extensions: call!(tls_extensions, extensions_len),
        || {
            let client_hello = ClientHello {
                tls_version: version,
                session_id: session_id,
                extensions: extensions
            };
            ParserResult::ClientHello(client_hello)
        }
    )
}

#[inline]
fn tls_server_hello<'a>(input: &'a [u8], _length: u32) -> IResult<&'a [u8], ParserResult> {
    chain!(input,
        version: switch!(be_u16,
            0x0002 => value!(TlsVersion::Ssl_2_0) |
            0x0300 => value!(TlsVersion::Ssl_3_0) |
            0x0301 => value!(TlsVersion::Tls_1_0) |
            0x0302 => value!(TlsVersion::Tls_1_1) |
            0x0303 => value!(TlsVersion::Tls_1_2) |
            0xfeff => value!(TlsVersion::Dtls_1_0) |
            0xfefd => value!(TlsVersion::Dtls_1_1)
        ) ~
        take!(32) ~ // Random
        session_len: be_u8 ~
        session_id: take!(session_len) ~ // SessionID
        cipher_suite: be_u16 ~
        compression_method: be_u8 ~
        extensions_len: opt!(be_u16) ~
        extensions: call!(tls_extensions, extensions_len),
        || {
            let server_hello = ServerHello {
                tls_version: version,
                session_id: session_id,
                cipher_suite: cipher_suite,
                compression_method: compression_method,
                extensions: extensions
            };
            ParserResult::ServerHello(server_hello)
        }
    )
}

#[inline]
fn ecdhe_named_curve<'a>(
    input: &'a [u8],
    length: u32,
    cipher_suite: u16,
) -> IResult<&'a [u8], ParserResult> {
    let result = chain!(input,
        kex_algo: switch!(be_u16,
            0x17 => value!(&ring::agreement::ECDH_P256) |
            0x18 => value!(&ring::agreement::ECDH_P384) |
            0x1d => value!(&ring::agreement::X25519)
        ) ~
        pubkey_len: be_u8 ~
        pubkey: take!(pubkey_len) ~
        sig_len: be_u16 ~
        sig: take!(sig_len),
        || {
            let params = KexParams::EcdheParams(EcdheParams {
                algo: kex_algo,
                pubkey: pubkey
            });
            ParserResult::ServerKeyExchange(ServerKeyExchange { params: params })
        }
    );

    match result {
        IResult::Done(leftover, parser) => IResult::Done(leftover, parser),
        _ => tls_handshake_unimplemented(input, length - 3),
    }
}

#[inline]
fn tls_server_kex_ecdhe<'a>(
    input: &'a [u8],
    length: u32,
    cipher_suite: u16,
) -> IResult<&'a [u8], ParserResult> {
    chain!(input,
        curve_type: switch!(be_u8,
            0x01 => value!(EcCurveType::ExplicitPrime) |
            0x02 => value!(EcCurveType::ExplicitChar) |
            0x03 => value!(EcCurveType::NamedCurve)
        ) ~
        result: cond_reduce!(curve_type == EcCurveType::NamedCurve, call!(ecdhe_named_curve, length, cipher_suite)),
        || {
            result
        }
    )
}

#[inline]
fn tls_server_key_exchange<'a>(
    input: &'a [u8],
    length: u32,
    cipher_suite: u16,
) -> IResult<&'a [u8], ParserResult> {
    let kex = match CIPHERS.get(&cipher_suite) {
        Some(val) => &val.kex,
        None => return tls_handshake_unimplemented(input, length),
    };

    match *kex {
        KexType::DHE => return tls_handshake_unimplemented(input, length),
        KexType::ECDHE => tls_server_kex_ecdhe(input, length, cipher_suite),
        _ => {
            warn!("Unsupported ServerKeyExchange for Kex type: {:?}", kex);
            return tls_handshake_unimplemented(input, length);
        }
    }
}

#[inline]
fn tls_client_key_exchange<'a>(
    input: &'a [u8],
    length: u32,
    cipher_suite: u16,
) -> IResult<&'a [u8], ParserResult> {
    let mut sig_type = SigType::Null;
    let kex = match CIPHERS.get(&cipher_suite) {
        Some(val) => {
            sig_type = val.kex_sig.clone();
            val.kex.clone()
        }
        None => KexType::Unknown,
    };
    chain!(input,
        kex_length: switch!(value!(kex.clone()),
            KexType::RSA => call!(be_u16) |
            KexType::DHE => call!(be_u16) |
            KexType::ECDHE => map!(be_u8, u16::from)
        ) ~
        data: cond_reduce!((kex_length as u32) < length, take!(kex_length)),
        || {
            let kex = ClientKeyExchange {
                kex_type: kex,
                sig_type: sig_type,
                data: data
            };
            ParserResult::ClientKeyExchange(kex)
        }
    )
}

#[inline]
fn tls_certificate<'a>(input: &'a [u8], length: u32) -> IResult<&'a [u8], ParserResult> {
    let mut server_cert = None;
    let mut first = true;
    let result: IResult<&[u8], bool> = chain!(input,
        mut certs_length: be_u24 ~
        many1!(chain!(
            cert_length: cond_reduce!(certs_length > 0, be_u24) ~
            cert: cond_reduce!(cert_length < length, take!(cert_length)),
            || {
                if first {
                    server_cert = Some(cert);
                    first = false;
                }
                certs_length -= cert_length + 3;
            })
        ),
        || {
            false
        }
    );
    let leftover = match result {
        IResult::Done(leftover, _) => leftover,
        _ => return tls_handshake_unimplemented(input, length),
    };

    if let Some(cert) = server_cert {
        IResult::Done(
            leftover,
            ParserResult::Certificate(Certificate { cert: cert }),
        )
    } else {
        tls_handshake_unimplemented(input, length)
    }
}
