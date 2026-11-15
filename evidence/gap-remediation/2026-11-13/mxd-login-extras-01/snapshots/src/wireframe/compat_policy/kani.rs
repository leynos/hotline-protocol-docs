//! Bounded invariants for preserving observed client metadata without classification.

use super::ClientCompatibility;
use crate::{protocol::VERSION, wireframe::connection::HandshakeMetadata};

#[kani::proof]
fn kani_preserves_handshake_and_login_versions() {
    let sub_version: u16 = kani::any();
    let login_version: u16 = kani::any();
    let handshake = HandshakeMetadata {
        sub_protocol: u32::from_be_bytes(*b"HOTL"),
        version: VERSION,
        sub_version,
    };
    let compat = ClientCompatibility::from_handshake(&handshake);
    compat.record_login_version(login_version);
    kani::assert(
        compat.handshake_sub_version() == sub_version,
        "handshake fact is preserved",
    );
    kani::assert(
        compat.login_version() == Some(login_version),
        "reported version is preserved",
    );
}
