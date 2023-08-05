use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
};

use sha2::{Digest, Sha256};
use std::{fs::File, path::Path, process::exit};

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

        let writer = File::create(STORE_URL)?;
        serde_json::to_writer(&writer, &mut store)?;

        println!("Store created!");
    }

    let mut store: Store = serde_json::from_reader(&store_file)?;

    // Create backup, File::create() will overwrite existing file
    let backup = File::create(BACKUP_URL)?;
    serde_json::to_writer(&backup, &mut store)?;

    // create write
    let store_file = File::create(STORE_URL)?;

    // if store is not empty, prompt login
    let master = match store.master.as_ref() {
        Some(master_pass) => {
            // prompt login
            println!("Enter master password: ");
            let mut input = String::with_capacity(256);
            std::io::stdin().read_line(&mut input)?;

            // match password with first record
            let hash = hash_str(&input);
            if &hash == master_pass {
                println!("Login successful!");
                hash
            } else {
                panic!("Login failed!");
            }
        }
        None => {
            // prompt first time setup
            println!("Set master password: ");
            let mut input = String::with_capacity(256);
            std::io::stdin().read_line(&mut input)?;

            println!("Confirm master password: ");
            let mut input2 = String::with_capacity(256);
            std::io::stdin().read_line(&mut input2)?;

            if input == input2 {
                store.master = Some(hash_str(&input));
                serde_json::to_writer(&store_file, &mut store)?;
                println!("Master password set!");
                hash_str(&input)
            } else {
                panic!("Passwords do not match!");
            }
        }
    };

    println!("Hashing master password...");
    let master_hash = hash_str(&master);

    println!("Creating key...");
    let key: &[u8; 32] = master_hash.as_bytes().try_into()?;
    let key = Key::<Aes256Gcm>::from_slice(key);
    // let key = CryptographyData::get_key(key);

    // let crypto = CryptographyData::generate(key);

    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let encrypt = |input: &str| -> Vec<u8> { cipher.encrypt(&nonce, input.as_bytes()).unwrap() };

    let decrypt = |input: &str| -> String {
        let deciphered = cipher.decrypt(&nonce, input.as_bytes()).unwrap();
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
                    name: String::from_utf8(encrypt(name)).unwrap(),
                    username: Some(String::from_utf8(encrypt(username)).unwrap()),
                    password: String::from_utf8(encrypt(password)).unwrap(),
                };

                store.entries.push(entry);
                serde_json::to_writer(&store_file, &mut store)?;
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

                let entry = store::Entry {
                    name: decrypt(&entry_cipher.name),
                    username: Some(username),
                    password: decrypt(&entry_cipher.password),
                };

                println!("Name: {}", entry.name);
                println!("Username: {}", entry.username.as_ref().unwrap());
                println!("Password: {}", entry.password);
            }

            Some("rm") => {
                let name = args.next().unwrap();
                let index = store
                    .entries
                    .iter()
                    .position(|entry| entry.name == name)
                    .unwrap();

                store.entries.remove(index);
                serde_json::to_writer(&store_file, &mut store)?;
                println!("Entry removed!");
            }

            Some("list") => {
                for entry in store.entries.iter() {
                    println!("{}", decrypt(&entry.name));
                }
            }

            Some("exit") => exit_safe(None, store, store_file),
            _ => {
                println!("Invalid command!");
            }
        }
    }
}

fn exit_safe(dbg: Option<&str>, mut store: Store, store_file: File) -> ! {
    serde_json::to_writer(&store_file, &mut store).unwrap();

    match dbg {
        Some(dbg) => panic!("{dbg}"),
        None => exit(0),
    }
}

fn hash_str(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    let result = hasher.finalize();
    format!("{:x}", result)
}

fn is_empty(input: &File) -> bool {
    let metadata = input.metadata().unwrap();
    metadata.len() == 0
}
