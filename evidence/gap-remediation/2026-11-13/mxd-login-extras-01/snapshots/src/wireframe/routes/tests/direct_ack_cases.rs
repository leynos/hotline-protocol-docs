//! Router-boundary direct reply contract tests.

use rstest::rstest;
use test_util::{AnyError, build_test_db, setup_files_db};

use super::helpers::{RouteTestContext, decode_reply_params, find_string, runtime};
use crate::{
    field_id::FieldId,
    transaction_type::TransactionType,
    wireframe::test_helpers::xor_bytes,
};

#[expect(clippy::panic_in_result_fn, reason = "test assertions")]
#[rstest]
fn direct_ack_login_success_uses_type_zero_and_correlation() -> Result<(), AnyError> {
    let rt = runtime()?;
    let test_db = build_test_db(&rt, setup_files_db)?
        .expect("the selected test profile must supply a database backend");
    let mut ctx = RouteTestContext::new(test_db.pool())?;
    let version = 190u16.to_be_bytes();
    let id = 0x1234_5678;

    let reply = rt.block_on(ctx.send(
        TransactionType::Login,
        id,
        &[
            (FieldId::Login, b"alice"),
            (FieldId::Password, b"secret"),
            (FieldId::Version, &version),
        ],
    ))?;
    assert_eq!(reply.header.is_reply, 1);
    assert_eq!(reply.header.ty, 0);
    assert_eq!(reply.header.id, id);
    assert_eq!(reply.header.error, 0);
    let params = decode_reply_params(&reply)?;
    assert_eq!(
        params
            .iter()
            .find(|(field, _)| *field == FieldId::BannerId)
            .map(|(_, bytes)| bytes.as_slice()),
        Some(&[0, 0][..])
    );
    assert_eq!(find_string(&params, FieldId::ServerName)?, "mxd");
    Ok(())
}

#[expect(clippy::panic_in_result_fn, reason = "test assertions")]
#[rstest]
fn direct_ack_sub_version_two_still_has_native_login_extras() -> Result<(), AnyError> {
    let rt = runtime()?;
    let test_db = build_test_db(&rt, setup_files_db)?
        .expect("the selected test profile must supply a database backend");
    let mut ctx = RouteTestContext::with_sub_version(test_db.pool(), 2)?;
    let id = 0x1234_5690;
    let reply = rt.block_on(ctx.send(
        TransactionType::Login,
        id,
        &[(FieldId::Login, b"alice"), (FieldId::Password, b"secret")],
    ))?;
    assert_eq!(
        (
            reply.header.is_reply,
            reply.header.ty,
            reply.header.id,
            reply.header.error
        ),
        (1, 0, id, 0)
    );
    let params = decode_reply_params(&reply)?;
    assert_eq!(
        params
            .iter()
            .find(|(field, _)| *field == FieldId::BannerId)
            .map(|(_, bytes)| bytes.as_slice()),
        Some(&[0, 0][..])
    );
    assert_eq!(find_string(&params, FieldId::ServerName)?, "mxd");
    Ok(())
}

#[rstest]
#[case(0)]
#[case(150)]
#[case(151)]
#[case(190)]
fn direct_ack_login_extras_ignore_reported_version(#[case] version: u16) -> Result<(), AnyError> {
    let rt = runtime()?;
    let test_db = build_test_db(&rt, setup_files_db)?
        .expect("the selected test profile must supply a database backend");
    let mut ctx = RouteTestContext::with_sub_version(test_db.pool(), 2)?;
    let id = u32::from(version) + 0x1234_6000;
    let version_bytes = version.to_be_bytes();
    let reply = rt.block_on(ctx.send(
        TransactionType::Login,
        id,
        &[
            (FieldId::Login, b"alice"),
            (FieldId::Password, b"secret"),
            (FieldId::Version, &version_bytes),
        ],
    ))?;
    anyhow::ensure!(
        (
            reply.header.is_reply,
            reply.header.ty,
            reply.header.id,
            reply.header.error
        ) == (1, 0, id, 0),
        "login ACK header differs for reported version {version}"
    );
    let params = decode_reply_params(&reply)?;
    anyhow::ensure!(
        params
            .iter()
            .find(|(field, _)| *field == FieldId::BannerId)
            .map(|(_, bytes)| bytes.as_slice())
            == Some(&[0, 0][..]),
        "field 161 is not the native two-byte value"
    );
    anyhow::ensure!(
        find_string(&params, FieldId::ServerName)? == "mxd",
        "default name differs"
    );
    Ok(())
}

#[rstest]
#[case("", false)]
#[case("1234567890123456789012345678901", false)]
#[case("mxd", true)]
fn direct_ack_configured_name_obeys_clear_and_xor_paths(
    #[case] name: &str,
    #[case] xor_enabled: bool,
) -> Result<(), AnyError> {
    let rt = runtime()?;
    let test_db = build_test_db(&rt, setup_files_db)?
        .expect("the selected test profile must supply a database backend");
    let mut ctx = RouteTestContext::with_configuration(test_db.pool(), 2, name, xor_enabled)?;
    let login = if xor_enabled {
        xor_bytes(b"alice")
    } else {
        b"alice".to_vec()
    };
    let password = if xor_enabled {
        xor_bytes(b"secret")
    } else {
        b"secret".to_vec()
    };
    let id = 0x1234_6780;
    let reply = rt.block_on(ctx.send(
        TransactionType::Login,
        id,
        &[
            (FieldId::Login, login.as_slice()),
            (FieldId::Password, password.as_slice()),
        ],
    ))?;
    anyhow::ensure!(
        (
            reply.header.is_reply,
            reply.header.ty,
            reply.header.id,
            reply.header.error
        ) == (1, 0, id, 0),
        "configured-name login ACK header differs"
    );
    let params = decode_reply_params(&reply)?;
    anyhow::ensure!(
        params
            .iter()
            .find(|(field, _)| *field == FieldId::BannerId)
            .map(|(_, bytes)| bytes.as_slice())
            == Some(&[0, 0][..]),
        "field 161 is not the native two-byte value"
    );
    let server_name = params
        .iter()
        .find(|(field, _)| *field == FieldId::ServerName)
        .map(|(_, bytes)| bytes.as_slice());
    let expected = name.as_bytes().to_vec();
    anyhow::ensure!(
        server_name == (!name.is_empty()).then_some(expected.as_slice()),
        "clear server-name bytes differ"
    );
    if xor_enabled {
        let encoded = ctx.xor().encode_payload(&reply.payload)?;
        let encoded_params = crate::transaction::decode_params(&encoded)?;
        let encoded_name = encoded_params
            .iter()
            .find(|(field, _)| *field == FieldId::ServerName)
            .map(|(_, bytes)| bytes.as_slice());
        let expected_encoded = xor_bytes(name.as_bytes());
        anyhow::ensure!(
            encoded_name == Some(expected_encoded.as_slice()),
            "XOR server-name bytes differ"
        );
    }
    Ok(())
}

#[expect(clippy::panic_in_result_fn, reason = "test assertions")]
#[rstest]
fn direct_ack_login_failure_uses_type_zero_without_extras() -> Result<(), AnyError> {
    let rt = runtime()?;
    let test_db = build_test_db(&rt, setup_files_db)?
        .expect("the selected test profile must supply a database backend");
    let mut ctx = RouteTestContext::new(test_db.pool())?;
    let version = 190u16.to_be_bytes();
    let id = 0x1234_5679;

    let reply = rt.block_on(ctx.send(
        TransactionType::Login,
        id,
        &[
            (FieldId::Login, b"alice"),
            (FieldId::Password, b"wrong-password"),
            (FieldId::Version, &version),
        ],
    ))?;
    assert_eq!(reply.header.is_reply, 1);
    assert_eq!(reply.header.ty, 0);
    assert_eq!(reply.header.id, id);
    assert_ne!(reply.header.error, 0);
    assert!(
        reply.payload.is_empty(),
        "failed login must have no success extras"
    );
    Ok(())
}

#[expect(clippy::panic_in_result_fn, reason = "test assertions")]
#[rstest]
fn direct_ack_nonlogin_uses_type_zero_and_correlation() -> Result<(), AnyError> {
    let rt = runtime()?;
    let test_db = build_test_db(&rt, setup_files_db)?
        .expect("the selected test profile must supply a database backend");
    let mut ctx = RouteTestContext::new(test_db.pool())?;
    let login = rt.block_on(ctx.send(
        TransactionType::Login,
        0x1234_5680,
        &[(FieldId::Login, b"alice"), (FieldId::Password, b"secret")],
    ))?;
    assert_eq!(login.header.error, 0);
    let id = 0x1234_5681;

    let reply = rt.block_on(ctx.send(TransactionType::GetFileNameList, id, &[]))?;
    assert_eq!(reply.header.is_reply, 1);
    assert_eq!(reply.header.ty, 0);
    assert_eq!(reply.header.id, id);
    assert_eq!(reply.header.error, 0);
    Ok(())
}
