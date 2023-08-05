use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
};

use sha2::{Digest, Sha256};
use std::{error::Error, fs::File, io::Write, path::Path, process::exit};

use crate::store::{CryptographyData, Store};
mod store;
// use clap::Parser;

// #[derive(Parser, Debug)]
// #[command(author, about, version)]
// struct Args {

// }

const STORE_URL: &str = r"C:\Temp\cpasswordstore\store.json";
const BACKUP_URL: &str = r"C:\Temp\cpasswordstore\store-bac.json";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // check if store exists
    if !Path::new(STORE_URL).exists() {
        println!("Store does not exist, creating...");
        File::create(STORE_URL)?;
        println!("Store created!");
    }

    let store_file = File::open(STORE_URL)?;

    // if store is empty, create new store
    if is_empty(&store_file) {
        println!("Store is empty, creating new store...");
        let mut store: Store = Store::empty();

        if !Path::new(BACKUP_URL).exists() {
            println!("Backup does not exist, creating...");
            let backup_file = File::open(BACKUP_URL)?;
            let mut backup: Store = serde_json::from_reader(&backup_file)?;
            serde_json::to_writer(&store_file, &mut backup)?;
            println!("Backup created!");
        }

        let writer = File::create(STORE_URL)?;
        serde_json::to_writer(&writer, &mut store)?;

        println!("Store created!");
    }

    let mut store: Store = serde_json::from_reader(&store_file)?;

    {
        // Create backup, File::create() will overwrite existing file
        let backup = File::create(BACKUP_URL)?;
        serde_json::to_writer(&backup, &mut store)?;
    }

    // create write
    let mut store_file = File::create(STORE_URL)?;

    // if store is not empty, prompt login, and hashes provided pass.
    let master = match store.master.as_ref() {
        Some(master_pass) => login_existing(master_pass)?,
        None => setup_new(&mut store, &store_file)?,
    };

    println!("Creating key...");

    assert_eq!(master.len(), 32, "Key length is not 32 bytes!");

    let key = Key::<Aes256Gcm>::from_slice(&master);
    // let key = CryptographyData::get_key(key);

    // let cipher = crypto.chipher;
    // let nonce = crypto.nonce;
    let cipher = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(&store.cryptography_data.nonce);

    let encrypt = |input: &str| -> Vec<u8> {
        cipher
            .encrypt(&nonce, input.as_bytes())
            .expect("Encryption failed!")
    };

    let decrypt = |input: &Vec<u8>| -> String {
        let deciphered = cipher
            .decrypt(&nonce, input.as_slice())
            .expect("Decryption failed!");
        String::from_utf8(deciphered).unwrap()
    };

    println!("Commands:");
    println!("add <name> <username> <password>      - add a new entry");
    println!("get <name>                            - get an entry");
    println!("rm <name>                             - remove an entry");
    println!("list                                  - list all entries");
    println!("exit                                  - exit the program");

    loop {
        let mut input = String::with_capacity(256);
        std::io::stdin().read_line(&mut input)?;

        let mut args = input.split_whitespace();

        match args.next() {
            Some("add") => {
                let name = match args.next() {
                    Some(name) => name,
                    None => {
                        println!("Invalid command!");
                        continue;
                    }
                };

                let username = match args.next() {
                    Some(username) => username,
                    None => {
                        println!("Invalid command!");
                        continue;
                    }
                };

                let password = match args.next() {
                    Some(password) => password,
                    None => {
                        println!("Invalid command!");
                        continue;
                    }
                };

                let entry = store::Entry {
                    name: name.to_string(),
                    username: Some(encrypt(username)),
                    password: encrypt(password),
                };

                store.entries.push(entry);
                // serde_json::to_writer(&store_file, &mut store)?;
                println!("Entry added!");
            }

            Some("get") => {
                let name = match args.next() {
                    Some(name) => name,
                    None => {
                        println!("Invalid command!");
                        continue;
                    }
                };

                let entry_cipher = match store
                    .entries
                    .iter()
                    .find(|entry_cipher| entry_cipher.name == name)
                {
                    Some(entry_cipher) => entry_cipher,
                    None => {
                        println!("Entry not found!");
                        continue;
                    }
                };

                let username = match &entry_cipher.username {
                    Some(username) => decrypt(&username),
                    None => String::from(""),
                };

                let password = decrypt(&entry_cipher.password);
                let name = entry_cipher.name.clone();

                println!("Name: {name}");
                println!("Username: {username}");
                println!("Password: {password}");
            }

            Some("rm") => {
                let name = args.next().unwrap();
                let index = store
                    .entries
                    .iter()
                    .position(|entry| entry.name == name)
                    .unwrap();

                store.entries.remove(index);
                // serde_json::to_writer(&store_file, &mut store)?;
                println!("Entry removed!");
            }

            Some("list") => {
                for entry in store.entries.iter() {
                    println!("{}", &entry.name);
                }
            }

            Some("exit") => exit_safe(None, store, &mut store_file),
            _ => {
                println!("Invalid command!");
            }
        }
    }
}

fn setup_new(store: &mut Store, store_file: &File) -> Result<Vec<u8>, Box<dyn Error>> {
    println!("Set master password: ");
    let mut input = String::with_capacity(256);
    std::io::stdin().read_line(&mut input)?;
    println!("Confirm master password: ");
    let mut input2 = String::with_capacity(256);
    std::io::stdin().read_line(&mut input2)?;

    let pass = if input == input2 {
        store.master = Some(hash(&input));

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        store.cryptography_data = CryptographyData {
            salt: Vec::new(),
            nonce: nonce.to_vec(),
        };

        serde_json::to_writer(store_file, store)?;
        println!("Master password set!");
        Ok(hash(&input))
    } else {
        println!("Passwords do not match!");
        exit(1);
    };
    exit(0);
    pass
}

fn login_existing(master_pass: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    println!("Enter master password: ");
    let mut input = String::with_capacity(256);
    std::io::stdin().read_line(&mut input)?;
    let hash = hash(&input);
    Ok(if &hash == master_pass {
        println!("Login successful!");
        hash
    } else {
        panic!("Login failed!");
    })
}

fn exit_safe(dbg: Option<&str>, mut store: Store, store_file: &mut File) -> ! {
    serde_json::to_writer(store_file, &mut store).unwrap();

    // write eof
    // store_file.flush().unwrap();

    match dbg {
        Some(dbg) => panic!("{dbg}"),
        None => exit(0),
    }
}

fn hash(input: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    result.to_vec()
}

fn is_empty(input: &File) -> bool {
    let metadata = input.metadata().unwrap();
    metadata.len() == 0
}
