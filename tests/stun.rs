//! STUN (RFC 5389) encoder/parser tests against the RFC byte layout — no network.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use dig_nat::stun::{
    encode_binding_request, parse_binding_response, StunError, ATTR_MAPPED_ADDRESS,
    ATTR_XOR_MAPPED_ADDRESS, BINDING_REQUEST, BINDING_SUCCESS, MAGIC_COOKIE,
};

const TXID: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

#[test]
fn binding_request_has_rfc_header() {
    let req = encode_binding_request(&TXID);
    assert_eq!(req.len(), 20);
    assert_eq!(u16::from_be_bytes([req[0], req[1]]), BINDING_REQUEST);
    assert_eq!(u16::from_be_bytes([req[2], req[3]]), 0, "no attributes");
    assert_eq!(
        u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
        MAGIC_COOKIE
    );
    assert_eq!(&req[8..20], &TXID);
}

/// Build a Binding success response with one XOR-MAPPED-ADDRESS (IPv4) and check the XOR is undone.
#[test]
fn parses_xor_mapped_ipv4() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 51234);
    let msg = build_response(ATTR_XOR_MAPPED_ADDRESS, addr, &TXID);
    let got = parse_binding_response(&msg, Some(&TXID)).unwrap();
    assert_eq!(got, addr);
}

#[test]
fn parses_xor_mapped_ipv6() {
    let addr = SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1234)),
        9450,
    );
    let msg = build_response(ATTR_XOR_MAPPED_ADDRESS, addr, &TXID);
    let got = parse_binding_response(&msg, Some(&TXID)).unwrap();
    assert_eq!(got, addr);
}

/// Legacy MAPPED-ADDRESS (non-XOR) is a fallback when no XOR attribute is present.
#[test]
fn parses_legacy_mapped_address_fallback() {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42)), 1234);
    let msg = build_response(ATTR_MAPPED_ADDRESS, addr, &TXID);
    let got = parse_binding_response(&msg, Some(&TXID)).unwrap();
    assert_eq!(got, addr);
}

#[test]
fn rejects_bad_magic_cookie() {
    let mut msg = build_response(
        ATTR_XOR_MAPPED_ADDRESS,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        &TXID,
    );
    msg[4] ^= 0xff; // corrupt the cookie
    assert_eq!(
        parse_binding_response(&msg, Some(&TXID)),
        Err(StunError::BadMagicCookie)
    );
}

#[test]
fn rejects_transaction_id_mismatch() {
    let msg = build_response(
        ATTR_XOR_MAPPED_ADDRESS,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        &TXID,
    );
    let other = [9u8; 12];
    assert_eq!(
        parse_binding_response(&msg, Some(&other)),
        Err(StunError::TransactionIdMismatch)
    );
}

#[test]
fn rejects_truncated() {
    assert_eq!(
        parse_binding_response(&[0u8; 4], None),
        Err(StunError::Truncated)
    );
}

#[test]
fn rejects_no_mapped_address() {
    // A valid Binding success header with zero attributes → no mapped address.
    let mut msg = Vec::new();
    msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(&TXID);
    assert_eq!(
        parse_binding_response(&msg, Some(&TXID)),
        Err(StunError::NoMappedAddress)
    );
}

#[test]
fn rejects_non_success_type() {
    // A Binding REQUEST is not a success response.
    let req = encode_binding_request(&TXID);
    assert!(matches!(
        parse_binding_response(&req, Some(&TXID)),
        Err(StunError::UnexpectedType(_))
    ));
}

/// Build a STUN Binding success response carrying `addr` in the given attribute type. For an
/// XOR attribute the value is XOR-obfuscated per RFC 5389 §15.2; for a plain MAPPED-ADDRESS it is not.
fn build_response(attr_type: u16, addr: SocketAddr, txid: &[u8; 12]) -> Vec<u8> {
    let xor = attr_type == ATTR_XOR_MAPPED_ADDRESS;
    let cookie_be = MAGIC_COOKIE.to_be_bytes();

    // Encode the attribute value.
    let mut value = Vec::new();
    value.push(0); // reserved
    match addr.ip() {
        IpAddr::V4(v4) => {
            value.push(0x01); // family IPv4
            let port = if xor {
                addr.port() ^ ((MAGIC_COOKIE >> 16) as u16)
            } else {
                addr.port()
            };
            value.extend_from_slice(&port.to_be_bytes());
            let mut octets = v4.octets();
            if xor {
                for (i, o) in octets.iter_mut().enumerate() {
                    *o ^= cookie_be[i];
                }
            }
            value.extend_from_slice(&octets);
        }
        IpAddr::V6(v6) => {
            value.push(0x02); // family IPv6
            let port = if xor {
                addr.port() ^ ((MAGIC_COOKIE >> 16) as u16)
            } else {
                addr.port()
            };
            value.extend_from_slice(&port.to_be_bytes());
            let mut octets = v6.octets();
            if xor {
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&cookie_be);
                key[4..].copy_from_slice(txid);
                for (o, k) in octets.iter_mut().zip(key.iter()) {
                    *o ^= *k;
                }
            }
            value.extend_from_slice(&octets);
        }
    }

    // Attribute header + value, padded to 4 bytes.
    let mut attr = Vec::new();
    attr.extend_from_slice(&attr_type.to_be_bytes());
    attr.extend_from_slice(&(value.len() as u16).to_be_bytes());
    attr.extend_from_slice(&value);
    while attr.len() % 4 != 0 {
        attr.push(0);
    }

    // Message header.
    let mut msg = Vec::new();
    msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    msg.extend_from_slice(&(attr.len() as u16).to_be_bytes());
    msg.extend_from_slice(&cookie_be);
    msg.extend_from_slice(txid);
    msg.extend_from_slice(&attr);
    msg
}
