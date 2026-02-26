// Copyright 2026, The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! TA functionality for beginning a crypto operation.

use super::{AuthInfo, CryptoOperation, Operation, CONFIRMATION_DATA_PREFIX};
use alloc::vec::Vec;
use kmr_common::{
    crypto::{aes, des, rsa, KeyMaterial, SymmetricOperation},
    get_bool_tag_value, get_opt_tag_value, get_tag_value, keyblob, km_err,
    tag::{characteristics_at, check_begin_params, digest_len, get_digest},
    try_to_vec, Error, FallibleAllocExt,
};
use kmr_wire::{
    keymint::{ErrorCode, HardwareAuthToken, KeyParam, KeyPurpose},
    secureclock::Timestamp,
    InternalBeginResult,
};
use log::{info, warn};

impl crate::KeyMintTa {
    pub(crate) fn begin_operation(
        &mut self,
        purpose: KeyPurpose,
        key_blob: &[u8],
        params: Vec<KeyParam>,
        auth_token: Option<HardwareAuthToken>,
    ) -> Result<InternalBeginResult, Error> {
        let op_idx = self.new_operation_index()?;

        // Parse and decrypt the keyblob, which requires extra hidden params.
        let (keyblob, sdd_slot) = self.keyblob_parse_decrypt(key_blob, &params)?;
        let keyblob::PlaintextKeyBlob { characteristics, key_material } = keyblob;

        // Validate parameters.
        let key_chars = characteristics_at(&characteristics, self.hw_info.security_level)?;
        check_begin_params(key_chars, purpose, &params)?;
        self.check_begin_auths(key_chars, key_blob)?;

        let trusted_conf_data = if purpose == KeyPurpose::Sign
            && get_bool_tag_value!(key_chars, TrustedConfirmationRequired)?
        {
            // Trusted confirmation is required; accumulate the signed data in an extra buffer,
            // starting with a prefix.
            Some(try_to_vec(CONFIRMATION_DATA_PREFIX)?)
        } else {
            None
        };

        let slot_to_delete = if let Some(&1) = get_opt_tag_value!(key_chars, UsageCountLimit)? {
            warn!("single-use key will be deleted on operation completion");
            sdd_slot
        } else {
            None
        };

        // At most one operation involving proof of user presence can be in-flight at a time.
        let presence_required = get_bool_tag_value!(key_chars, TrustedUserPresenceRequired)?;
        if presence_required && self.presence_required_op.is_some() {
            return Err(km_err!(
                ConcurrentProofOfPresenceRequested,
                "additional op with proof-of-presence requested"
            ));
        }

        let mut op_auth_info = AuthInfo::new(key_chars)?;
        if let Some(auth_info) = &op_auth_info {
            // Authentication checks are required on begin() if there's a timeout that
            // we can check.
            if let Some(timeout_secs) = auth_info.timeout_secs {
                if let Some(clock) = &self.imp.clock {
                    let now: Timestamp = clock.now().into();
                    let auth_token = auth_token.ok_or_else(|| {
                        km_err!(KeyUserNotAuthenticated, "no auth token on begin()")
                    })?;
                    self.check_auth_token(
                        auth_token,
                        auth_info,
                        Some(now),
                        Some(timeout_secs),
                        None,
                    )?;

                    // Auth already checked, nothing needed on subsequent calls
                    op_auth_info = None;
                } else if let Some(auth_token) = auth_token {
                    self.check_auth_token(auth_token, auth_info, None, None, None)?;
                }
            }
        }

        // Re-use the same random value for both:
        // - op_handle: the way to identify which operation is involved
        // - challenge: the value used as part of the input for authentication tokens
        let op_handle = self.new_op_handle();
        let challenge = op_handle.0;
        let mut ret_params = Vec::new();
        let op = match key_material {
            KeyMaterial::Aes(key) => {
                let caller_nonce = get_opt_tag_value!(&params, Nonce)?.map(Vec::as_ref);
                let mode = aes::Mode::new(&params, caller_nonce, &mut *self.imp.rng)?;
                let dir = match purpose {
                    KeyPurpose::Encrypt => SymmetricOperation::Encrypt,
                    KeyPurpose::Decrypt => SymmetricOperation::Decrypt,
                    _ => {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "invalid purpose {purpose:?} for AES key",
                        ))
                    }
                };
                if caller_nonce.is_none() {
                    // Need to return any randomly-generated nonce to the caller.
                    match &mode {
                        aes::Mode::Cipher(aes::CipherMode::EcbNoPadding)
                        | aes::Mode::Cipher(aes::CipherMode::EcbPkcs7Padding) => {}
                        aes::Mode::Cipher(aes::CipherMode::CbcNoPadding { nonce: n })
                        | aes::Mode::Cipher(aes::CipherMode::CbcPkcs7Padding { nonce: n }) => {
                            ret_params.try_push(KeyParam::Nonce(try_to_vec(n)?))?
                        }
                        aes::Mode::Cipher(aes::CipherMode::Ctr { nonce: n }) => {
                            ret_params.try_push(KeyParam::Nonce(try_to_vec(n)?))?
                        }
                        aes::Mode::Aead(aes::GcmMode::GcmTag12 { nonce: n })
                        | aes::Mode::Aead(aes::GcmMode::GcmTag13 { nonce: n })
                        | aes::Mode::Aead(aes::GcmMode::GcmTag14 { nonce: n })
                        | aes::Mode::Aead(aes::GcmMode::GcmTag15 { nonce: n })
                        | aes::Mode::Aead(aes::GcmMode::GcmTag16 { nonce: n }) => {
                            ret_params.try_push(KeyParam::Nonce(try_to_vec(n)?))?
                        }
                    }
                }
                match &mode {
                    aes::Mode::Cipher(mode) => Operation {
                        handle: op_handle,
                        aad_allowed: false,
                        input_size: 0,
                        slot_to_delete,
                        trusted_conf_data,
                        auth_info: op_auth_info,
                        crypto_op: CryptoOperation::Aes(self.imp.aes.begin(key, *mode, dir)?),
                    },
                    aes::Mode::Aead(mode) => Operation {
                        handle: op_handle,
                        aad_allowed: true,
                        input_size: 0,
                        slot_to_delete,
                        trusted_conf_data,
                        auth_info: op_auth_info,
                        crypto_op: CryptoOperation::AesGcm(
                            self.imp.aes.begin_aead(key, *mode, dir)?,
                        ),
                    },
                }
            }
            KeyMaterial::TripleDes(key) => {
                let caller_nonce = get_opt_tag_value!(&params, Nonce)?.map(Vec::as_ref);
                let mode = des::Mode::new(&params, caller_nonce, &mut *self.imp.rng)?;
                let dir = match purpose {
                    KeyPurpose::Encrypt => SymmetricOperation::Encrypt,
                    KeyPurpose::Decrypt => SymmetricOperation::Decrypt,
                    _ => {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "invalid purpose {purpose:?} for DES key",
                        ))
                    }
                };
                if caller_nonce.is_none() {
                    // Need to return any randomly-generated nonce to the caller.
                    match &mode {
                        des::Mode::EcbNoPadding | des::Mode::EcbPkcs7Padding => {}
                        des::Mode::CbcNoPadding { nonce: n }
                        | des::Mode::CbcPkcs7Padding { nonce: n } => {
                            ret_params.try_push(KeyParam::Nonce(try_to_vec(n)?))?
                        }
                    }
                }
                Operation {
                    handle: op_handle,
                    aad_allowed: false,
                    input_size: 0,
                    slot_to_delete,
                    trusted_conf_data,
                    auth_info: op_auth_info,
                    crypto_op: CryptoOperation::Des(self.imp.des.begin(key, mode, dir)?),
                }
            }
            KeyMaterial::Hmac(key) => {
                let digest = get_digest(&params)?;

                Operation {
                    handle: op_handle,
                    aad_allowed: false,
                    input_size: 0,
                    slot_to_delete,
                    trusted_conf_data,
                    auth_info: op_auth_info,
                    crypto_op: match purpose {
                        KeyPurpose::Sign => {
                            let tag_len =
                                get_tag_value!(&params, MacLength, ErrorCode::MissingMacLength)?
                                    as usize
                                    / 8;
                            CryptoOperation::HmacSign(self.imp.hmac.begin(key, digest)?, tag_len)
                        }
                        KeyPurpose::Verify => {
                            // Remember the acceptable tag lengths.
                            let min_tag_len = get_tag_value!(
                                key_chars,
                                MinMacLength,
                                ErrorCode::MissingMinMacLength
                            )? as usize
                                / 8;
                            let max_tag_len = digest_len(digest)? as usize;
                            CryptoOperation::HmacVerify(
                                self.imp.hmac.begin(key, digest)?,
                                min_tag_len..max_tag_len,
                            )
                        }
                        _ => {
                            return Err(km_err!(
                                IncompatiblePurpose,
                                "invalid purpose {purpose:?} for HMAC key",
                            ))
                        }
                    },
                }
            }
            KeyMaterial::Rsa(key) => Operation {
                handle: op_handle,
                aad_allowed: false,
                input_size: 0,
                slot_to_delete,
                trusted_conf_data,
                auth_info: op_auth_info,
                crypto_op: match purpose {
                    KeyPurpose::Decrypt => {
                        let mode = rsa::DecryptionMode::new(&params)?;
                        CryptoOperation::RsaDecrypt(self.imp.rsa.begin_decrypt(key, mode)?)
                    }
                    KeyPurpose::Sign => {
                        let mode = rsa::SignMode::new(&params)?;
                        CryptoOperation::RsaSign(self.imp.rsa.begin_sign(key, mode)?)
                    }
                    _ => {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "invalid purpose {purpose:?} for RSA key",
                        ))
                    }
                },
            },
            KeyMaterial::Ec(_, _, key) => Operation {
                handle: op_handle,
                aad_allowed: false,
                input_size: 0,
                slot_to_delete,
                trusted_conf_data,
                auth_info: op_auth_info,
                crypto_op: match purpose {
                    KeyPurpose::AgreeKey => CryptoOperation::EcAgree(self.imp.ec.begin_agree(key)?),
                    KeyPurpose::Sign => {
                        let digest = get_digest(&params)?;
                        CryptoOperation::EcSign(self.imp.ec.begin_sign(key, digest)?)
                    }
                    _ => {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "invalid purpose {purpose:?} for EC key",
                        ))
                    }
                },
            },
            KeyMaterial::MlDsa(_variant, key) => Operation {
                handle: op_handle,
                aad_allowed: false,
                input_size: 0,
                slot_to_delete,
                trusted_conf_data,
                auth_info: op_auth_info,
                crypto_op: match purpose {
                    KeyPurpose::Sign => CryptoOperation::MlDsaSign(self.imp.mldsa.begin_sign(key)?),
                    _ => {
                        return Err(km_err!(
                            IncompatiblePurpose,
                            "invalid purpose {purpose:?} for ML-DSA key",
                        ))
                    }
                },
            },
        };
        self.operations[op_idx] = Some(op);
        if presence_required {
            info!("this operation requires proof-of-presence");
            self.presence_required_op = Some(op_handle);
        }
        Ok(InternalBeginResult { challenge, params: ret_params, op_handle: op_handle.0 })
    }

    /// Check TA-specific key authorizations on `begin()`.
    fn check_begin_auths(&mut self, key_chars: &[KeyParam], key_blob: &[u8]) -> Result<(), Error> {
        if self.dev.bootloader.done() && get_bool_tag_value!(key_chars, BootloaderOnly)? {
            return Err(km_err!(
                InvalidKeyBlob,
                "attempt to use bootloader-only key after bootloader done"
            ));
        }
        if !self.in_early_boot && get_bool_tag_value!(key_chars, EarlyBootOnly)? {
            return Err(km_err!(EarlyBootEnded, "attempt to use EARLY_BOOT key after early boot"));
        }

        if let Some(max_uses) = get_opt_tag_value!(key_chars, MaxUsesPerBoot)? {
            // Track the use count for this key.
            let key_id = self.key_id(key_blob)?;
            self.update_use_count(key_id, *max_uses)?;
        }
        Ok(())
    }
}
