use aes_gcm::aead::OsRng;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize, Clone)]
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

pub fn random_text(len: usize) -> String {
    let mut rng = OsRng;
    let mut str = String::with_capacity(len);
    for _ in 0..len {
        str.push(rng.gen_range(33_u8..127) as char);
    }
    str
}

/// Returns a tuple of (salted master, salt)
fn salt_secret(secret: &[u8], salt: &[u8]) -> String {
    let concatenated = format!(
        "{}{}",
        String::from_utf8_lossy(secret),
        String::from_utf8_lossy(salt)
    );

    concatenated
}

pub fn hash_and_salt(secret: &[u8], salt: &[u8]) -> Vec<u8> {
    let master_salted = salt_secret(secret, salt);
    hash(&master_salted)
}

pub fn generate_salt(secret_length: usize) -> Vec<u8> {
    let mut rng = OsRng;
    let mut salt = vec![0u8; secret_length];
    rng.fill_bytes(&mut salt);
    salt
}
