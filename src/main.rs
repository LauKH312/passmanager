use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
};

use std::{error::Error, fs::File, path::Path, process::exit};

use crate::crypto_utils::CryptographyData;
use crate::store::Store;

mod crypto_utils;
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
        println!("Store does not exist, creating store file...");
        File::create(STORE_URL)?;
        println!("Store file created!");
    }

    let store_file = File::open(STORE_URL)?;

    // if store is empty, create new store or restore from backup
    if is_empty(&store_file) {
        match Path::new(BACKUP_URL).exists() {
            true => {
                println!("Backup exists, restoring...");
                match load_from_backup() {
                    Ok(_) => println!("Restored from backup!"),
                    Err(e) => println!("Restoring backup failed! {e}"),
                }
                exit(0);
            }
            false => {
                println!("Store is empty, creating new store...");
                let mut store: Store = Store::empty();
                let writer = File::create(STORE_URL)?;
                serde_json::to_writer(&writer, &mut store)?;
                println!("Store created!");
                exit(0);
            }
        }
    }

    // load store
    let mut store: Store = serde_json::from_reader(&store_file)?;

    {
        // Create backup, later File::create() will overwrite existing file
        let backup = File::create(BACKUP_URL)?;
        serde_json::to_writer(&backup, &mut store)?;
    }

    // create write
    let mut store_writer = File::create(STORE_URL)?;

    // if store is not empty, prompt login, and hashes provided pass.
    let master = match store.master.as_ref() {
        Some(master_pass) => login_existing(master_pass),
        None => match get_new_master_password() {
            Ok(master) => {
                let master_hash = String::from_utf8(master.clone()).unwrap();
                let master_hash = crypto_utils::hash(&master_hash);

                store.master = Some(master_hash);

                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

                store.cryptography_data = CryptographyData {
                    salt: Vec::new(),
                    nonce: nonce.to_vec(),
                };

                // serde_json::to_writer(&store_writer, &store)?;

                println!("Successfully created new key!");
                Ok(master)
            }
            Err(e) => {
                println!("{e}");
                exit_safe(None, store, &mut store_writer);
            }
        },
    };

    if let Err(e) = master {
        // println!("Login failed!");
        println!("{e}");
        exit_safe(None, store, &mut store_writer);
    } else {
        println!("Login successful!");
    }

    let mut master = master.unwrap();

    while master.len() < 32 {
        master.push(0);
    }

    assert_eq!(master.len(), 32, "Key length is not 32 bytes!");

    let key = Key::<Aes256Gcm>::from_slice(master.as_slice());

    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&store.cryptography_data.nonce);

    let encrypt = |input: &str| -> Vec<u8> {
        cipher
            .encrypt(nonce, input.as_bytes())
            .expect("Encryption failed!")
    };

    let decrypt = |input: &Vec<u8>| -> String {
        let deciphered = cipher
            .decrypt(nonce, input.as_slice())
            .expect("Decryption failed!");
        String::from_utf8(deciphered).unwrap()
    };

    println!(
        r"
    -------------------------------
    Commands:
    add <name> <username> <password>
    generate <name> <username>
    get <name>
    rm <name>
    list
    exit
    -------------------------------
    "
    );

    loop {
        println!();
        println!("---------------------");
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
                    username: Some(encrypt(username)),
                    password: encrypt(password),
                };

                store.entries.insert(name.to_string(), entry);
                // serde_json::to_writer(&store_file, &mut store)?;
                println!("Entry added!");
            }

            Some("generate") => {
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

                let password = crypto_utils::random_text(32);
                println!("Generated password: [{password}]");

                let entry = store::Entry {
                    username: Some(encrypt(username)),
                    password: encrypt(&password),
                };

                store.entries.insert(name.to_string(), entry);
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
                    .find(|(key, _entry_cipher)| key.as_str() == name)
                {
                    Some(entry_cipher) => entry_cipher,
                    None => {
                        println!("Entry not found!");
                        continue;
                    }
                };

                let username = match &entry_cipher.1.username {
                    Some(username) => decrypt(username),
                    None => String::from(""),
                };

                let password = decrypt(&entry_cipher.1.password);
                let name = entry_cipher.0.clone();

                println!("Name: {name}");
                println!("Username: {username}");
                println!("Password: {password}");
            }

            Some("rm") => {
                let name = args.next().unwrap();
                let _index = store
                    .entries
                    .iter()
                    .position(|(key, _entry)| key == name)
                    .unwrap();

                store.entries.remove(name);
                // serde_json::to_writer(&store_file, &mut store)?;
                println!("Entry removed!");
            }

            Some("list") => {
                println!("vvvvvv");
                // print sorted list of entries
                let mut entries: Vec<&String> = store.entries.keys().collect();
                entries.sort();
                for entry in entries {
                    println!("{entry}");
                }
            }

            Some("exit") => exit_safe(None, store, &mut store_writer),
            _ => {
                println!("Invalid command!");
            }
        }
    }
}

fn load_from_backup() -> Result<(), Box<dyn Error>> {
    let store_file = File::create(STORE_URL)?;
    let backup_file = File::open(BACKUP_URL)?;
    let mut backup: Store = serde_json::from_reader(&backup_file)?;
    serde_json::to_writer(store_file, &mut backup)?;

    Ok(())
}

fn get_new_master_password() -> Result<Vec<u8>, Box<dyn Error>> {
    println!("Set master password: ");
    let mut input = String::with_capacity(256);
    std::io::stdin().read_line(&mut input)?;
    println!("Confirm master password: ");
    let mut input2 = String::with_capacity(256);
    std::io::stdin().read_line(&mut input2)?;

    match input == input2 {
        true => Ok(input.into_bytes()),
        false => Err("Passwords do not match!".into()),
    }
}

fn login_existing(master_pass: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
    println!("Enter master password: ");
    let mut input = String::with_capacity(256);
    std::io::stdin().read_line(&mut input)?;
    let hash = crypto_utils::hash(&input);
    if &hash == master_pass {
        println!("Login successful!");
        Ok(input.into_bytes())
    } else {
        Err("Password is incorrect!".into())
    }
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

fn is_empty(input: &File) -> bool {
    let metadata = input.metadata().unwrap();
    metadata.len() == 0
}
