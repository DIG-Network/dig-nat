//! Minimal STUN (RFC 5389) client — discover this node's *reflexive* (public) transport address.
//!
//! A NAT'd node cannot see the `ip:port` the outside world dials it on. STUN answers that: the node
//! sends a **Binding request** to a STUN server (the DIG relay runs one; any RFC-5389 STUN server
//! also works) and the server replies with a **Binding success response** carrying the node's
//! reflexive address in an `XOR-MAPPED-ADDRESS` attribute. That reflexive `ip:port` is the
//! **server-reflexive candidate** dig-nat advertises so a remote peer can attempt a direct dial or
//! a coordinated hole-punch.
//!
//! We implement the small datagram directly (RFC 5389 §6, §15.2) rather than pulling a STUN crate:
//! it is a fixed 20-byte header + TLV attributes, so encoding/parsing is tiny and every branch is
//! unit-testable against the RFC byte layout with no network. The relay's STUN server is expected
//! to speak this exact wire; if the sibling agent's dig-relay STUN implementation diverges, this is
//! the module to reconcile (see the crate-level reconciliation note).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

/// STUN magic cookie (RFC 5389 §6). Always the first 4 bytes after the message type + length.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Binding request message type (RFC 5389 §6 — method Binding = 0x001, class Request = 0b00).
pub const BINDING_REQUEST: u16 = 0x0001;
/// Binding success response message type (method Binding, class Success = 0b10).
pub const BINDING_SUCCESS: u16 = 0x0101;

/// `XOR-MAPPED-ADDRESS` attribute type (RFC 5389 §15.2).
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// Legacy `MAPPED-ADDRESS` attribute type (RFC 5389 §15.1) — some servers still emit it.
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;

/// Address family markers inside a (XOR-)MAPPED-ADDRESS attribute.
const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// Errors decoding a STUN response or performing a Binding transaction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StunError {
    /// The datagram was shorter than a valid STUN message / attribute.
    #[error("STUN message truncated")]
    Truncated,
    /// The magic cookie did not match — not a STUN (RFC 5389) message.
    #[error("bad STUN magic cookie")]
    BadMagicCookie,
    /// The transaction id in the response did not match the request (possible spoof / stale reply).
    #[error("STUN transaction id mismatch")]
    TransactionIdMismatch,
    /// The message parsed but carried no usable mapped-address attribute.
    #[error("no mapped address in STUN response")]
    NoMappedAddress,
    /// The message type was not a Binding success response.
    #[error("unexpected STUN message type: {0:#06x}")]
    UnexpectedType(u16),
    /// Underlying socket I/O error (stringified so [`StunError`] stays `Clone`/`Eq`).
    #[error("STUN io: {0}")]
    Io(String),
    /// The transaction did not complete within the deadline.
    #[error("STUN request timed out")]
    Timeout,
}

/// A STUN Binding request: 20-byte header (type, length=0, cookie, 96-bit transaction id) and no
/// attributes. `transaction_id` is caller-supplied so the response can be matched to the request.
pub fn encode_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);
    msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes()); // message type
    msg.extend_from_slice(&0u16.to_be_bytes()); // message length (no attributes)
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes()); // magic cookie
    msg.extend_from_slice(transaction_id); // 96-bit transaction id
    msg
}

/// Parse a STUN **Binding success response**, returning the reflexive [`SocketAddr`] from its
/// `XOR-MAPPED-ADDRESS` (preferred) or legacy `MAPPED-ADDRESS` attribute.
///
/// Validates the magic cookie and (when `expected_txid` is `Some`) the transaction id, so a stale
/// or spoofed datagram is rejected. Implements the XOR de-obfuscation of RFC 5389 §15.2.
pub fn parse_binding_response(
    msg: &[u8],
    expected_txid: Option<&[u8; 12]>,
) -> Result<SocketAddr, StunError> {
    if msg.len() < 20 {
        return Err(StunError::Truncated);
    }
    let msg_type = u16::from_be_bytes([msg[0], msg[1]]);
    let msg_len = u16::from_be_bytes([msg[2], msg[3]]) as usize;
    let cookie = u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(StunError::BadMagicCookie);
    }
    if msg_type != BINDING_SUCCESS {
        return Err(StunError::UnexpectedType(msg_type));
    }
    let txid: [u8; 12] = msg[8..20].try_into().map_err(|_| StunError::Truncated)?;
    if let Some(expected) = expected_txid {
        if &txid != expected {
            return Err(StunError::TransactionIdMismatch);
        }
    }
    if msg.len() < 20 + msg_len {
        return Err(StunError::Truncated);
    }

    // Walk the TLV attributes. Prefer XOR-MAPPED-ADDRESS; fall back to MAPPED-ADDRESS.
    let mut fallback: Option<SocketAddr> = None;
    let mut off = 20usize;
    let end = 20 + msg_len;
    while off + 4 <= end {
        let attr_type = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let attr_len = u16::from_be_bytes([msg[off + 2], msg[off + 3]]) as usize;
        let val_start = off + 4;
        let val_end = val_start + attr_len;
        if val_end > end {
            return Err(StunError::Truncated);
        }
        let value = &msg[val_start..val_end];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                return decode_mapped_address(value, &txid, true);
            }
            ATTR_MAPPED_ADDRESS if fallback.is_none() => {
                fallback = decode_mapped_address(value, &txid, false).ok();
            }
            _ => {}
        }
        // Attributes are padded to a 4-byte boundary (RFC 5389 §15).
        off = val_end + ((4 - (attr_len % 4)) % 4);
    }
    fallback.ok_or(StunError::NoMappedAddress)
}

/// Decode a (XOR-)MAPPED-ADDRESS attribute value into a [`SocketAddr`].
///
/// Layout (RFC 5389 §15.1/§15.2): `[reserved:1][family:1][port:2][address:4 or 16]`. When `xor` is
/// set, the port is XORed with the top 16 bits of the magic cookie and the address is XORed with the
/// full cookie (IPv4) or cookie‖transaction-id (IPv6).
fn decode_mapped_address(
    value: &[u8],
    txid: &[u8; 12],
    xor: bool,
) -> Result<SocketAddr, StunError> {
    if value.len() < 4 {
        return Err(StunError::Truncated);
    }
    let family = value[1];
    let raw_port = u16::from_be_bytes([value[2], value[3]]);
    let cookie_be = MAGIC_COOKIE.to_be_bytes();
    let port = if xor {
        raw_port ^ ((MAGIC_COOKIE >> 16) as u16)
    } else {
        raw_port
    };

    match family {
        FAMILY_IPV4 => {
            if value.len() < 8 {
                return Err(StunError::Truncated);
            }
            let mut octets = [value[4], value[5], value[6], value[7]];
            if xor {
                for (i, o) in octets.iter_mut().enumerate() {
                    *o ^= cookie_be[i];
                }
            }
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        FAMILY_IPV6 => {
            if value.len() < 20 {
                return Err(StunError::Truncated);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            if xor {
                // XOR key is the 32-bit cookie followed by the 96-bit transaction id.
                let mut key = [0u8; 16];
                key[..4].copy_from_slice(&cookie_be);
                key[4..].copy_from_slice(txid);
                for (o, k) in octets.iter_mut().zip(key.iter()) {
                    *o ^= *k;
                }
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => Err(StunError::UnexpectedType(other as u16)),
    }
}

/// Perform a single STUN Binding transaction against `server` over `socket`, returning the
/// discovered reflexive (public) [`SocketAddr`] of `socket`. Bounded by `timeout`; a lost datagram
/// surfaces as [`StunError::Timeout`] (the caller retries or falls through to the next method).
///
/// The `socket` should be the very UDP socket whose external mapping the caller wants to learn —
/// the reflexive address is specific to the NAT binding created by *that* socket.
pub async fn query_reflexive_address(
    socket: &UdpSocket,
    server: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr, StunError> {
    let txid = new_transaction_id();
    let req = encode_binding_request(&txid);
    socket
        .send_to(&req, server)
        .await
        .map_err(|e| StunError::Io(e.to_string()))?;

    let mut buf = [0u8; 512];
    let recv = tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await;
    let (n, _from) = match recv {
        Ok(Ok(x)) => x,
        Ok(Err(e)) => return Err(StunError::Io(e.to_string())),
        Err(_) => return Err(StunError::Timeout),
    };
    parse_binding_response(&buf[..n], Some(&txid))
}

/// Generate a 96-bit transaction id. Uses the current time + socket-ish entropy; STUN only needs it
/// to be unpredictable enough to match a response to a request, not cryptographically random.
fn new_transaction_id() -> [u8; 12] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut id = [0u8; 12];
    id.copy_from_slice(&now.to_le_bytes()[..12]);
    id
}
