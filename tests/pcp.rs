//! PCP (RFC 6887) MAP datagram encode/parse tests against the RFC byte layout — no network.

use std::net::{IpAddr, Ipv4Addr};

use dig_nat::method::pcp::{
    encode_map_request, new_nonce, parse_map_response, MapNonce, PcpError, OP_MAP, PCP_VERSION,
    PROTO_UDP, RESPONSE_BIT,
};

const NONCE: MapNonce = [7, 6, 5, 4, 3, 2, 1, 0, 9, 8, 7, 6];

#[test]
fn map_request_layout() {
    let client = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
    let req = encode_map_request(&NONCE, false, 4444, 4444, 7200, client);
    assert_eq!(req.len(), 60, "24-byte header + 36-byte MAP body");
    assert_eq!(req[0], PCP_VERSION);
    assert_eq!(req[1], OP_MAP, "request: R bit clear");
    assert_eq!(u32::from_be_bytes([req[4], req[5], req[6], req[7]]), 7200);
    // MAP body nonce at offset 24.
    assert_eq!(&req[24..36], &NONCE);
    assert_eq!(req[36], PROTO_UDP);
    assert_eq!(
        u16::from_be_bytes([req[40], req[41]]),
        4444,
        "internal port"
    );
    assert_eq!(
        u16::from_be_bytes([req[42], req[43]]),
        4444,
        "suggested ext port"
    );
}

#[test]
fn parses_map_response_ipv4() {
    let msg = build_map_response(&NONCE, 0, 5555, Ipv4Addr::new(203, 0, 113, 9), 3600);
    let resp = parse_map_response(&msg, &NONCE).unwrap();
    assert_eq!(resp.external_port, 5555);
    assert_eq!(resp.external_ip, IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)));
    assert_eq!(resp.lifetime_secs, 3600);
    assert_eq!(resp.nonce, NONCE);
}

#[test]
fn rejects_nonce_mismatch() {
    let msg = build_map_response(&NONCE, 0, 5555, Ipv4Addr::LOCALHOST, 60);
    let other = [0u8; 12];
    assert_eq!(
        parse_map_response(&msg, &other),
        Err(PcpError::NonceMismatch)
    );
}

#[test]
fn rejects_nonzero_result() {
    let msg = build_map_response(&NONCE, 8, 0, Ipv4Addr::LOCALHOST, 0); // result 8 = NO_RESOURCES
    assert_eq!(
        parse_map_response(&msg, &NONCE),
        Err(PcpError::ResultCode(8))
    );
}

#[test]
fn rejects_bad_version() {
    let mut msg = build_map_response(&NONCE, 0, 1, Ipv4Addr::LOCALHOST, 1);
    msg[0] = 0xff;
    assert_eq!(
        parse_map_response(&msg, &NONCE),
        Err(PcpError::BadVersion(0xff))
    );
}

#[test]
fn rejects_wrong_opcode() {
    let mut msg = build_map_response(&NONCE, 0, 1, Ipv4Addr::LOCALHOST, 1);
    msg[1] = 0x00; // not a MAP response
    assert_eq!(
        parse_map_response(&msg, &NONCE),
        Err(PcpError::UnexpectedOpcode(0x00))
    );
}

#[test]
fn rejects_truncated() {
    assert_eq!(
        parse_map_response(&[0u8; 10], &NONCE),
        Err(PcpError::Truncated)
    );
}

// ---- #179 MEDIUM: PCP MAP nonce must come from a CSPRNG, not wall-clock time ----
//
// Regression for SECURITY_AUDIT_P2P.md `## dig-nat` finding 3: `new_nonce` used to copy
// `SystemTime::now()` nanoseconds (little-endian) into all 12 bytes of the MAP nonce, the identical
// predictable pattern as the STUN transaction id (finding 1). `parse_map_response`'s nonce check is
// the sole anti-spoof validator for a MAP response, so a predictable nonce lets an attacker on the
// gateway path forge a MAP success with a guessed nonce and misdirect the assigned external
// port/IP. RFC 6887 SS11.1 requires the nonce be unpredictable.

#[test]
fn nonces_are_not_sequential_wall_clock_samples() {
    let nonces: Vec<MapNonce> = (0..64).map(|_| new_nonce()).collect();

    for i in 0..nonces.len() {
        for j in (i + 1)..nonces.len() {
            assert_ne!(
                nonces[i], nonces[j],
                "nonces must not collide across samples"
            );
        }
    }

    // The old implementation packed nanoseconds-since-epoch little-endian into 12 bytes, leaving
    // bytes 8..12 (the high-order 32 bits of the 96-bit field) zero for centuries. A CSPRNG must
    // vary those bytes.
    assert!(
        nonces.iter().any(|n| n[8..12] != [0u8, 0, 0, 0]),
        "high-order bytes must vary — a wall-clock-nanosecond source leaves them zero"
    );
}

#[test]
fn nonce_is_not_derived_from_current_time() {
    let now_nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let nonce = new_nonce();
    let low8 = u64::from_le_bytes(nonce[0..8].try_into().unwrap());
    assert_ne!(
        low8, now_nanos as u64,
        "MAP nonce must not equal the wall-clock nanosecond timestamp"
    );
}

/// Build a PCP MAP response: 24-byte header (version, opcode|R, reserved, result, lifetime, epoch,
/// reserved) + 36-byte MAP body (nonce, proto, reserved, internal, external, external ip).
fn build_map_response(
    nonce: &MapNonce,
    result: u8,
    external_port: u16,
    external_ip: Ipv4Addr,
    lifetime: u32,
) -> Vec<u8> {
    let mut msg = vec![0u8; 60];
    msg[0] = PCP_VERSION;
    msg[1] = OP_MAP | RESPONSE_BIT;
    msg[3] = result;
    msg[4..8].copy_from_slice(&lifetime.to_be_bytes());
    // MAP body at offset 24.
    msg[24..36].copy_from_slice(nonce);
    msg[36] = PROTO_UDP;
    msg[42..44].copy_from_slice(&external_port.to_be_bytes());
    // external ip as IPv4-mapped IPv6 (bytes 44..60).
    let mapped = external_ip.to_ipv6_mapped().octets();
    msg[44..60].copy_from_slice(&mapped);
    msg
}
