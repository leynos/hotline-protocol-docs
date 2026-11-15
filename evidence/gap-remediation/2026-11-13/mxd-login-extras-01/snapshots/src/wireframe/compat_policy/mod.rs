//! Preserve observed handshake and login metadata and add native login fields.
//!
//! Sub-version 2 is shared by multiple clients, and the reported login version
//! does not establish peer identity or govern successful-login extras.

use std::sync::atomic::{AtomicU32, Ordering};

use crate::{
    field_id::FieldId,
    transaction::{
        Transaction,
        TransactionError,
        decode_params,
        encode_params,
        read_u16,
        read_u32,
    },
    transaction_type::TransactionType,
    wireframe::connection::HandshakeMetadata,
};

#[cfg(kani)]
mod kani;

const UNKNOWN_LOGIN_VERSION: u32 = u32::MAX;
const OPAQUE_LOGIN_FIELD_161: [u8; 2] = [0, 0];

/// Mutable compatibility state for a single connection.
#[derive(Debug)]
pub struct ClientCompatibility {
    handshake_sub_version: u16,
    login_version: AtomicU32,
}

impl ClientCompatibility {
    /// Seed a compatibility policy from handshake metadata.
    #[must_use]
    pub const fn from_handshake(handshake: &HandshakeMetadata) -> Self {
        Self {
            handshake_sub_version: handshake.sub_version,
            login_version: AtomicU32::new(UNKNOWN_LOGIN_VERSION),
        }
    }

    /// Record the client version observed in the login request.
    pub fn record_login_version(&self, version: u16) {
        self.login_version
            .store(u32::from(version), Ordering::Relaxed);
    }

    /// Return the recorded login version, if available.
    #[must_use]
    pub fn login_version(&self) -> Option<u16> {
        let version = self.login_version.load(Ordering::Relaxed);
        (version != UNKNOWN_LOGIN_VERSION)
            .then_some(version)
            .and_then(|raw| u16::try_from(raw).ok())
    }

    /// Return the observed handshake sub-version without inferring peer identity.
    #[must_use]
    pub const fn handshake_sub_version(&self) -> u16 { self.handshake_sub_version }

    /// Capture the login version from the login request payload.
    ///
    /// # Errors
    ///
    /// Returns a [`TransactionError`] when the payload cannot be decoded.
    pub fn record_login_payload(&self, payload: &[u8]) -> Result<(), TransactionError> {
        if let Some(version) = extract_login_version(payload)? {
            self.record_login_version(version);
        }
        Ok(())
    }

    /// Augment a successful login reply with opaque field 161 and the server name.
    ///
    /// Returns `true` if the reply was modified.
    ///
    /// # Errors
    ///
    /// Returns a [`TransactionError`] if the reply payload cannot be decoded or
    /// re-encoded.
    pub fn augment_login_reply(
        &self,
        request_type: TransactionType,
        reply: &mut Transaction,
        server_name: &[u8],
    ) -> Result<bool, TransactionError> {
        if !is_successful_login_reply(request_type, reply) {
            return Ok(false);
        }
        let mut params = decode_params(&reply.payload)?;
        let has_field_161 = params.iter().any(|(id, _)| *id == FieldId::BannerId);
        let has_server_name = params.iter().any(|(id, _)| *id == FieldId::ServerName);
        let mut changed = false;

        if !has_field_161 {
            params.push((FieldId::BannerId, OPAQUE_LOGIN_FIELD_161.to_vec()));
            changed = true;
        }
        if !has_server_name && !server_name.is_empty() {
            params.push((FieldId::ServerName, server_name.to_vec()));
            changed = true;
        }

        if !changed {
            return Ok(false);
        }

        reply.payload = encode_params(&params)?;
        let payload_len =
            u32::try_from(reply.payload.len()).map_err(|_| TransactionError::PayloadTooLarge)?;
        reply.header.total_size = payload_len;
        reply.header.data_size = payload_len;
        Ok(true)
    }
}

fn is_successful_login_reply(request_type: TransactionType, reply: &Transaction) -> bool {
    request_type == TransactionType::Login
        && reply.header.is_reply == 1
        && reply.header.ty == 0
        && reply.header.error == 0
}

fn extract_login_version(payload: &[u8]) -> Result<Option<u16>, TransactionError> {
    let params = decode_params(payload)?;
    for (field, data) in params {
        if field == FieldId::Version {
            return Ok(parse_login_version(&data));
        }
    }
    Ok(None)
}

fn parse_login_version(data: &[u8]) -> Option<u16> {
    match data.len() {
        2 => read_u16(data).ok(),
        4 => read_u32(data).ok().and_then(|raw| u16::try_from(raw).ok()),
        _ => None,
    }
}

#[cfg(test)]
#[path = "../compat_policy_tests.rs"]
mod tests;
