// Copyright (c) 2016-2017 Chef Software Inc. and/or applicable contributors
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

use std::str;

use base64;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::PublicKey as BoxPublicKey;
use sodiumoxide::crypto::box_::curve25519xsalsa20poly1305::SecretKey as BoxSecretKey;
use sodiumoxide::crypto::sealedbox;

use error::{Error, Result};

pub fn mk_box_public_key(key: &str) -> Result<BoxPublicKey> {
    let bytes = base64::decode(key).map_err(|e| {
        Error::CryptoError(format!("Failed to decode key: {:?}", e))
    })?;

    match BoxPublicKey::from_slice(&bytes) {
        Some(k) => Ok(k),
        None => Err(Error::CryptoError(format!("Failed to parse key"))),
    }
}

pub fn mk_box_secret_key(key: &str) -> Result<BoxSecretKey> {
    let bytes = base64::decode(key).map_err(|e| {
        Error::CryptoError(format!("Failed to decode key: {:?}", e))
    })?;

    match BoxSecretKey::from_slice(&bytes) {
        Some(k) => Ok(k),
        None => Err(Error::CryptoError(format!("Failed to parse key"))),
    }
}

pub fn encrypt(data: &[u8], pk: &str) -> Result<Vec<u8>> {
    let receiver_pk = mk_box_public_key(pk)?;
    Ok(sealedbox::seal(data, &receiver_pk))
}

pub fn decrypt(data: &[u8], pk: &str, sk: &str) -> Result<Vec<u8>> {
    let receiver_pk = mk_box_public_key(pk)?;
    let receiver_sk = mk_box_secret_key(sk)?;

    sealedbox::open(data, &receiver_pk, &receiver_sk).map_err(|e| {
        Error::CryptoError(format!("Failed to open box: {:?}", e))
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str;

    #[test]
    fn encrypt_and_decrypt_data() {
        let plaintext = "I am a disco dancer";
        let public_key = "Lvl4pup5vDMdOL5iNmXfLVdqEO1jCnXtCejGlbCfQko=";
        let secret_key = "8VoAmRLYKEpi9+iSZxYsceIXxLW8ytJLS5maHDmpFfw=";

        let encrypted = match encrypt(plaintext.as_bytes(), &public_key) {
            Ok(v) => v,
            Err(e) => panic!("Failed to encrypt data with sealed box: {:?}", e),
        };

        let decrypted = match decrypt(&encrypted[..], &public_key, &secret_key) {
            Ok(v) => v,
            Err(e) => panic!("Failed to decrypt data with sealed box: {:?}", e),
        };

        assert_eq!(plaintext.as_bytes(), &decrypted[..]);
    }
}
