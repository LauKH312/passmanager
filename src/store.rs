use crate::crypto_utils::CryptographyData;
use std::collections::HashMap;

use aes_gcm::{
    aead::{self, Aead, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Store {
    pub master: Option<Vec<u8>>,
    pub entries: HashMap<String, Entry>,
}

impl Store {
    pub fn empty() -> Store {
        Store {
            master: None,
            entries: HashMap::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Entry {
    pub password: Vec<u8>,
    pub username: Option<Vec<u8>>,
    pub cryptography_data: CryptographyData,
}

impl Entry {
    pub fn new(password_encrypted: Vec<u8>, username_encrypted: Option<Vec<u8>>) -> Entry {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce = nonce.to_vec();

        let salt = crate::crypto_utils::random_bytes(12);

        Entry {
            password: password_encrypted,
            username: username_encrypted,
            cryptography_data: CryptographyData { salt, nonce },
        }
    }

    pub fn encrypt(&mut self, data: &[u8], master_password: &Vec<u8>) -> Vec<u8> {
        let mut data = data.to_vec();

        let salt_avail_space = 32 - data.len();
        if salt_avail_space >= 4 {
            self.cryptography_data.salt.truncate(salt_avail_space);
            data.extend(self.cryptography_data.salt.clone());
        }

        let key = Key::<Aes256Gcm>::from_slice(master_password);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(&self.cryptography_data.nonce);
        cipher.encrypt(nonce, data.as_slice()).unwrap()
    }

    pub fn decrypt(&self, master_password: &[u8]) -> aead::Result<Entry> {
        let mut entry = self.to_owned();

        let key = Key::<Aes256Gcm>::from_slice(master_password);
        let cipher = Aes256Gcm::new(&key);
        let nonce = self.cryptography_data.nonce.clone();
        let decrypted = cipher.decrypt(Nonce::from_slice(&nonce), entry.password.as_slice())?;

        let salt_len = 32 - decrypted.len();
        let salt = &decrypted[salt_len..];
        let password = &decrypted[..salt_len];

        entry.password = password.to_vec();
        entry.cryptography_data.salt = salt.to_vec();

        if let Some(username) = &entry.username {
            let decrypted = cipher.decrypt(Nonce::from_slice(&nonce), username.as_slice())?;
            let salt_len = 32 - decrypted.len();
            let salt = &decrypted[salt_len..];
            let username = &decrypted[..salt_len];

            entry.username = Some(username.to_vec());
            entry.cryptography_data.salt = salt.to_vec();
        }

        Ok(entry)
    }

    pub fn from_unencrypted(
        username: Option<&[u8]>,
        password: &Vec<u8>,
        master_password: &Vec<u8>,
    ) -> Entry {
        let mut entry = Entry::new(password.clone(), username.map(|username| username.to_vec()));

        entry.password = entry.encrypt(password, master_password);
        entry.username = entry
            .username
            .clone()
            .map(|username| entry.encrypt(&username, master_password));
        return entry;
    }
}
