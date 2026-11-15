//! Regression tests for wireframe compatibility policies.
//!
//! These cases preserve raw metadata and the successful-login extras contract.
use rstest::rstest;

use super::*;
use crate::{
    commands::ERR_NOT_AUTHENTICATED,
    protocol::VERSION,
    transaction::{FrameHeader, Transaction, encode_params},
};

fn handshake(sub_version: u16) -> HandshakeMetadata {
    HandshakeMetadata {
        sub_protocol: u32::from_be_bytes(*b"HOTL"),
        version: VERSION,
        sub_version,
    }
}

fn reply_header(payload_len: usize) -> FrameHeader {
    let payload_len = match u32::try_from(payload_len) {
        Ok(payload_len) => payload_len,
        Err(err) => panic!("payload length fits in u32: {err}"),
    };
    FrameHeader {
        flags: 0,
        is_reply: 1,
        ty: 0,
        id: 1,
        error: 0,
        total_size: payload_len,
        data_size: payload_len,
    }
}

#[rstest]
#[case(0)]
#[case(2)]
fn preserves_handshake_sub_version_without_identity(#[case] sub_version: u16) {
    let compat = ClientCompatibility::from_handshake(&handshake(sub_version));
    assert_eq!(compat.handshake_sub_version(), sub_version);
}

#[rstest]
fn records_login_version_from_u16_payload() {
    let compat = ClientCompatibility::from_handshake(&handshake(0));
    let payload = encode_params(&[(FieldId::Version, [0u8, 151u8])]).expect("payload encodes");

    compat
        .record_login_payload(&payload)
        .expect("record login version");

    assert_eq!(compat.login_version(), Some(151));
}

#[rstest]
fn records_login_version_from_u32_payload() {
    let compat = ClientCompatibility::from_handshake(&handshake(0));
    let payload =
        encode_params(&[(FieldId::Version, [0u8, 0u8, 0u8, 190u8])]).expect("payload encodes");

    compat
        .record_login_payload(&payload)
        .expect("record login version");

    assert_eq!(compat.login_version(), Some(190));
}

fn assert_login_reply_augmentation(
    sub_version: u16,
    login_version: Option<u16>,
    server_name: &[u8],
) {
    let compat = ClientCompatibility::from_handshake(&handshake(sub_version));
    if let Some(version) = login_version {
        compat.record_login_version(version);
    }
    let payload = Vec::new();
    let header = reply_header(payload.len());
    let mut reply = Transaction { header, payload };

    let updated = match compat.augment_login_reply(TransactionType::Login, &mut reply, server_name)
    {
        Ok(updated) => updated,
        Err(err) => panic!("augment reply: {err}"),
    };

    assert!(updated);
    let params = match decode_params(&reply.payload) {
        Ok(params) => params,
        Err(err) => panic!("decode reply params: {err}"),
    };
    let mut expected = vec![(FieldId::BannerId, vec![0, 0])];
    if !server_name.is_empty() {
        expected.push((FieldId::ServerName, server_name.to_vec()));
    }
    assert_eq!(params, expected);
}

#[rstest]
#[case(0, None)]
#[case(0, Some(0))]
#[case(0, Some(150))]
#[case(0, Some(151))]
#[case(0, Some(190))]
#[case(2, None)]
#[case(2, Some(190))]
fn augments_every_successful_login(#[case] sub_version: u16, #[case] version: Option<u16>) {
    assert_login_reply_augmentation(sub_version, version, b"mxd");
}

#[rstest]
fn empty_name_omits_field_162() { assert_login_reply_augmentation(2, None, b""); }

#[rstest]
fn does_not_augment_successful_nonlogin_direct_reply() {
    let compat = ClientCompatibility::from_handshake(&handshake(0));
    compat.record_login_version(190);
    let payload = encode_params(&[(FieldId::Version, [0u8, 190u8])]).expect("payload encodes");
    let mut reply = Transaction {
        header: reply_header(payload.len()),
        payload: payload.clone(),
    };

    let changed = compat
        .augment_login_reply(TransactionType::GetFileNameList, &mut reply, b"mxd")
        .expect("augmentation checks request kind");
    assert!(!changed);
    assert_eq!(reply.payload, payload);
}

fn assert_not_augmented_for(version: u16, is_reply: u16, error: u32) {
    let compat = ClientCompatibility::from_handshake(&handshake(0));
    compat.record_login_version(version);
    #[expect(
        clippy::big_endian_bytes,
        reason = "network protocol uses big-endian integers"
    )]
    let payload = match encode_params(&[(FieldId::Version, version.to_be_bytes().as_ref())]) {
        Ok(payload) => payload,
        Err(err) => panic!("payload encodes: {err}"),
    };
    let payload_len = match u32::try_from(payload.len()) {
        Ok(payload_len) => payload_len,
        Err(err) => panic!("payload length fits in u32: {err}"),
    };
    let is_reply = match u8::try_from(is_reply) {
        Ok(is_reply) => is_reply,
        Err(err) => panic!("is_reply fits in u8: {err}"),
    };
    let header = FrameHeader {
        flags: 0,
        is_reply,
        ty: 0,
        id: 1,
        error,
        total_size: payload_len,
        data_size: payload_len,
    };
    let mut txn = Transaction {
        header,
        payload: payload.clone(),
    };

    let updated = match compat.augment_login_reply(TransactionType::Login, &mut txn, b"mxd") {
        Ok(updated) => updated,
        Err(err) => panic!("augment reply: {err}"),
    };

    assert!(!updated, "augmentation must not occur");
    assert_eq!(txn.payload, payload);
}

#[test]
fn does_not_augment_failed_login_reply_for_hotline_clients() {
    assert_not_augmented_for(190, 1, ERR_NOT_AUTHENTICATED);
}

#[test]
fn does_not_augment_login_request_for_hotline_clients() { assert_not_augmented_for(190, 0, 0); }

#[rstest]
fn records_u16_max_version_without_sentinel_collision() {
    let compat = ClientCompatibility::from_handshake(&handshake(0));
    compat.record_login_version(u16::MAX);
    assert_eq!(compat.login_version(), Some(u16::MAX));
}

#[rstest]
fn augment_login_reply_is_idempotent_when_extras_exist() {
    let compat = ClientCompatibility::from_handshake(&handshake(0));
    compat.record_login_version(190);
    #[expect(
        clippy::big_endian_bytes,
        reason = "network protocol uses big-endian integers"
    )]
    let payload = encode_params(&[
        (FieldId::Version, 190u16.to_be_bytes().as_ref()),
        (FieldId::BannerId, [0u8, 0u8].as_ref()),
        (FieldId::ServerName, b"mxd".as_ref()),
    ])
    .expect("payload encodes");
    let original_payload = payload.clone();
    let header = reply_header(payload.len());
    let mut reply = Transaction { header, payload };

    let updated = compat
        .augment_login_reply(TransactionType::Login, &mut reply, b"mxd")
        .expect("augment reply");

    assert!(!updated, "extras are already present");
    assert_eq!(reply.payload, original_payload);
}

#[rstest]
fn record_login_payload_ignores_unparsable_version_lengths() {
    let compat = ClientCompatibility::from_handshake(&handshake(0));
    let payload = encode_params(&[(FieldId::Version, vec![1u8, 2u8, 3u8].as_slice())])
        .expect("payload encodes");

    compat
        .record_login_payload(&payload)
        .expect("record login payload");

    assert_eq!(compat.login_version(), None);
    assert_eq!(compat.handshake_sub_version(), 0);
}
