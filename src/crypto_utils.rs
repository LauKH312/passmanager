use aes_gcm::{aead::OsRng, KeyInit};
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

#[derive(Debug, Serialize, Deserialize)]
pub struct CryptographyData {
    pub salt: Vec<u8>,
    pub nonce: Vec<u8>,
}

pub fn hash(input: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    result.to_vec()
}

#[allow(dead_code)]
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = OsRng;
    let mut bytes = vec![0u8; len];
    rng.fill_bytes(&mut bytes);
    bytes
}

pub fn random_text(len: usize) -> String {
    let mut rng = OsRng;
    let mut str = String::with_capacity(len);
    for _ in 0..len {
        str.push(rng.gen_range(33_u8..127) as char);
    }
    str
}
