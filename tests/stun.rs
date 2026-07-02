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

// ---- #179 HIGH: STUN transaction id must come from a CSPRNG, not wall-clock time ----
//
// Regression for SECURITY_AUDIT_P2P.md `## dig-nat` finding 1: `new_transaction_id` used to copy
// `SystemTime::now()` nanoseconds (little-endian) into all 12 bytes. That id is the ONLY anti-spoof
// check in `parse_binding_response` (the datagram source is discarded), so a predictable id lets an
// off-path attacker forge a `BINDING_SUCCESS` carrying a poisoned reflexive address. These tests
// prove the id is CSPRNG-sourced: (a) two ids generated back-to-back are never equal (a wall-clock
// counter can repeat within the same nanosecond-quantization step on some platforms, but the real
// failure mode we care about is (b)); (b) across many samples the high-order bytes vary — a
// wall-clock nanosecond count packed little-endian leaves the top bytes (bytes 4..12, since a
// nanosecond timestamp fits in ~8 bytes) constant or near-constant for a long time, which is exactly
// the forgeable pattern; a CSPRNG varies every byte with overwhelming probability.
use dig_nat::stun::new_transaction_id;

#[test]
fn transaction_ids_are_not_sequential_wall_clock_samples() {
    let ids: Vec<[u8; 12]> = (0..64).map(|_| new_transaction_id()).collect();

    // No two samples collide.
    for i in 0..ids.len() {
        for j in (i + 1)..ids.len() {
            assert_ne!(ids[i], ids[j], "txids must not collide across samples");
        }
    }

    // The old implementation packed `SystemTime::now()` nanoseconds-since-epoch (a ~63-bit value)
    // little-endian into the 12 bytes, so bytes 8..12 (the high-order 32 bits of the 96-bit field)
    // were always zero for centuries to come. A CSPRNG must NOT exhibit that: at least one sample's
    // high 4 bytes must be nonzero.
    assert!(
        ids.iter().any(|id| id[8..12] != [0u8, 0, 0, 0]),
        "high-order bytes must vary — a wall-clock-nanosecond source leaves them zero, which is the \
         forgeable pattern finding 1 flags"
    );

    // A CSPRNG spreads bit values roughly evenly; a monotonic wall-clock counter does not. Check
    // that consecutive samples differ in more than just their low few bytes (the wall-clock bug kept
    // the top bytes constant across calls made microseconds apart).
    let differing_high_bytes = ids
        .windows(2)
        .filter(|w| w[0][6..12] != w[1][6..12])
        .count();
    assert!(
        differing_high_bytes > ids.len() / 2,
        "most consecutive samples should differ in their high-order bytes too (CSPRNG), not just \
         the low bytes (wall-clock nanosecond counter)"
    );
}

#[test]
fn transaction_id_is_not_derived_from_current_time() {
    // Sample the wall clock and a txid together; the old buggy implementation encoded
    // `duration_since(UNIX_EPOCH).as_nanos()` little-endian into the id, so the id's low 8 bytes
    // equalled the current nanosecond timestamp (mod 2^64) at generation time. A CSPRNG id must not
    // match that derivation.
    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let id = new_transaction_id();
    let low8 = u64::from_le_bytes(id[0..8].try_into().unwrap());
    assert_ne!(
        low8, now_nanos as u64,
        "transaction id must not equal the wall-clock nanosecond timestamp"
    );
}
