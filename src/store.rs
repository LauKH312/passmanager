use std::collections::HashMap;
use crate::crypto_utils::CryptographyData;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Store {
    pub master: Option<Vec<u8>>,
    pub entries: HashMap<String, Entry>,
    pub cryptography_data: CryptographyData,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    pub password: Vec<u8>,
    pub username: Option<Vec<u8>>,
}

impl Store {
    pub fn empty() -> Store {
        Store {
            master: None,
            entries: HashMap::new(),
            cryptography_data: CryptographyData {
                salt: Vec::new(),
                nonce: Vec::new(),
            },
        }
    }
}
