use aes_gcm::{aead::generic_array::GenericArray, Aes256Gcm, KeyInit, aes::Aes256};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Store {
    pub master: Option<Vec<u8>>,
    pub entries: Vec<Entry>,
    pub cryptography_data: CryptographyData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub password: Vec<u8>,
    pub username: Option<Vec<u8>>,
}

impl Store {
    pub fn empty() -> Store {
        Store {
            master: None,
            entries: Vec::new(),
            cryptography_data: CryptographyData {
                salt: Vec::new(),
                nonce: Vec::new(),
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptographyData {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
}
impl CryptographyData {
    pub fn get_key(key: &[u8]) -> Aes256Gcm {
        let key = GenericArray::from_slice(key);
        Aes256Gcm::new(key)
    }

    pub fn generate(key: Aes256Gcm) -> Self {

        todo!()
    }
}
