use crate::STORE_PATH;
use std::{collections::HashMap, error::Error, fs::File};

use aes_gcm::{
    aead::{self, Aead, OsRng},
    AeadCore, Aes256Gcm, Key, KeyInit, Nonce,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Store {
    pub master: Option<Vec<u8>>,
    pub master_salt: Option<Vec<u8>>,
    pub entries: HashMap<String, Entry>,
}

impl Store {
    pub fn empty() -> Store {
        Store {
            master: None,
            master_salt: None,
            entries: HashMap::new(),
        }
    }

    pub fn create() -> Result<(), Box<dyn Error>> {
        println!("Store is empty, creating new store...");
        let store: Store = Store::empty();
        let writer = File::create(STORE_PATH)?;
        serde_json::to_writer(&writer, &store)?;
        println!("Store created!");
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Entry {
    pub password: Vec<u8>,
    pub username: Option<Vec<u8>>,
    pub nonce: Vec<u8>,
}

impl Entry {
    pub fn new(password_encrypted: Vec<u8>, username_encrypted: Option<Vec<u8>>) -> Entry {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce = nonce.to_vec();

        Entry {
            password: password_encrypted,
            username: username_encrypted,
            nonce,
        }
    }

    pub fn encrypt(&mut self, data: &[u8], master_password: &[u8]) -> Vec<u8> {
        assert!(data.len() <= 32);

        let key = Key::<Aes256Gcm>::from_slice(master_password);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&self.nonce);
        cipher.encrypt(nonce, data).unwrap()
    }

    pub fn decrypt(&self, master_password: &[u8]) -> aead::Result<Entry> {
        let mut entry = self.to_owned();

        let key = Key::<Aes256Gcm>::from_slice(master_password);
        let cipher = Aes256Gcm::new(key);
        let nonce = self.nonce.clone();
        let decrypted = cipher.decrypt(Nonce::from_slice(&nonce), entry.password.as_slice())?;

        assert!(decrypted.len() <= 32);

        let password = &decrypted;

        entry.password = password.to_vec();

        if let Some(username) = &entry.username {
            let decrypted = cipher.decrypt(Nonce::from_slice(&nonce), username.as_slice())?;

            entry.username = Some(decrypted.to_vec());
        }

        Ok(entry)
    }

    pub fn from_unencrypted(
        username: Option<&[u8]>,
        password: &[u8],
        master_password: &[u8],
    ) -> Entry {
        let mut entry = Entry::new(
            password.to_owned(),
            username.map(|username| username.to_vec()),
        );

        entry.password = entry.encrypt(password, master_password);
        entry.username = username.map(|username| entry.encrypt(username, master_password));

        entry
    }
}

/// Copies the contents of origin_path to destination_path, overwriting any file at destination_path.
pub fn filecpy(destination_path: &str, origin_path: &str) -> Result<(), Box<dyn Error>> {
    println!("Store is empty, restoring from backup...");
    let mut origin = File::create(destination_path)?;
    let mut destination = File::open(origin_path)?;
    std::io::copy(&mut destination, &mut origin)?;

    Ok(())
}

pub fn is_empty(input: &File) -> bool {
    let metadata = input.metadata().unwrap();
    metadata.len() == 0
}
