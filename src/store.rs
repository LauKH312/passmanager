use aes_gcm::aead::generic_array::GenericArray;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Store {
    pub master: Option<String>,
    pub entries: Vec<Entry>,
    pub cryptography_data: CryptographyData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub password: String,
    pub username: Option<String>,
}

impl Store {
    pub fn empty() -> Store {
        Store {
            master: None,
            entries: Vec::new(),
            cryptography_data: CryptographyData {
                salt: Vec::new(),
                nonce: Vec::new(),
                chipher: Vec::new(),
            },
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptographyData {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
    pub chipher: Vec<u8>,
}
impl CryptographyData {
    // pub fn generate(key: &GenericArray<u8, u8>) -> &[u8] {
    //     todo!()
    // }

    // pub fn encrypt(&self, key: &GenericArray<u8, u8>, plaintext: &str) -> &[u8] {
    //     todo!()
    // }

    // pub fn decrypt(&self, key: &GenericArray<u8, u8>, cyphertext: &str) -> &[u8] {
    //     todo!()
    // }
}
