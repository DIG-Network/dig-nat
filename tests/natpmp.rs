//! NAT-PMP (RFC 6886) datagram encode/parse tests against the RFC byte layout — no network.

use std::net::Ipv4Addr;

use dig_nat::method::natpmp::{
    encode_external_address_request, encode_map_request, parse_external_address_response,
    parse_map_response, NatPmpError, OP_EXTERNAL_ADDRESS, OP_MAP_UDP, RESPONSE_FLAG,
};

#[test]
fn external_address_request_is_two_bytes() {
    let req = encode_external_address_request();
    assert_eq!(req, [0u8, OP_EXTERNAL_ADDRESS]); // version 0, opcode 0
}

#[test]
fn map_request_layout() {
    // internal 4444, suggested external 4444, lifetime 7200.
    let req = encode_map_request(false, 4444, 4444, 7200);
    assert_eq!(req.len(), 12);
    assert_eq!(req[0], 0, "version 0");
    assert_eq!(req[1], OP_MAP_UDP);
    assert_eq!(&req[2..4], &[0, 0], "reserved");
    assert_eq!(u16::from_be_bytes([req[4], req[5]]), 4444);
    assert_eq!(u16::from_be_bytes([req[6], req[7]]), 4444);
    assert_eq!(u32::from_be_bytes([req[8], req[9], req[10], req[11]]), 7200);
}

#[test]
fn parses_external_address_response() {
    let mut msg = vec![0u8; 12];
    msg[1] = OP_EXTERNAL_ADDRESS + RESPONSE_FLAG; // response opcode
    msg[2..4].copy_from_slice(&0u16.to_be_bytes()); // result success
    msg[4..8].copy_from_slice(&1234u32.to_be_bytes()); // seconds
    msg[8..12].copy_from_slice(&[203, 0, 113, 5]); // external ip
    let resp = parse_external_address_response(&msg).unwrap();
    assert_eq!(resp.seconds_since_epoch, 1234);
    assert_eq!(resp.external_ip, Ipv4Addr::new(203, 0, 113, 5));
}

#[test]
fn parses_map_response() {
    let mut msg = vec![0u8; 16];
    msg[1] = OP_MAP_UDP + RESPONSE_FLAG;
    msg[2..4].copy_from_slice(&0u16.to_be_bytes()); // success
    msg[8..10].copy_from_slice(&4444u16.to_be_bytes()); // internal
    msg[10..12].copy_from_slice(&5555u16.to_be_bytes()); // external assigned
    msg[12..16].copy_from_slice(&3600u32.to_be_bytes()); // lifetime
    let resp = parse_map_response(&msg, false).unwrap();
    assert_eq!(resp.internal_port, 4444);
    assert_eq!(resp.external_port, 5555);
    assert_eq!(resp.lifetime_secs, 3600);
}

#[test]
fn rejects_nonzero_result_code() {
    let mut msg = vec![0u8; 12];
    msg[1] = OP_EXTERNAL_ADDRESS + RESPONSE_FLAG;
    msg[2..4].copy_from_slice(&2u16.to_be_bytes()); // result = 2 (not supported)
    assert_eq!(
        parse_external_address_response(&msg),
        Err(NatPmpError::ResultCode(2))
    );
}

#[test]
fn rejects_wrong_opcode() {
    let mut msg = vec![0u8; 12];
    msg[1] = 0x99; // not a valid response opcode
    assert_eq!(
        parse_external_address_response(&msg),
        Err(NatPmpError::UnexpectedOpcode(0x99))
    );
}

#[test]
fn rejects_truncated() {
    assert_eq!(
        parse_external_address_response(&[0u8; 4]),
        Err(NatPmpError::Truncated)
    );
    assert_eq!(
        parse_map_response(&[0u8; 4], false),
        Err(NatPmpError::Truncated)
    );
}
