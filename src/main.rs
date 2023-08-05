use std::{error::Error, fs::File, ops::ControlFlow, path::Path, process::exit};

use crate::store::{Entry, Store};

mod crypto_utils;
mod process;
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
                };
            }
            false => {
                println!("Store is empty, creating new store...");
                let mut store: Store = Store::empty();
                let writer = File::create(STORE_URL)?;
                serde_json::to_writer(&writer, &mut store)?;
                println!("Store created!");
            }
        };
        exit(0);
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
        Some(master_hash) => prompt_login(master_hash),

        // Handle case where master password is not set.
        // Matches if user has properly set the new master password.
        None => match prompt_new_master_password() {
            Ok(master) => {
                let master_hash = String::from_utf8(master.clone()).unwrap();
                let master_hash = crypto_utils::hash(&master_hash);

                store.master = Some(master_hash);

                println!("Successfully created new key!");
                Ok(master)
            }
            Err(e) => {
                println!("{e}");
                process::exit_safe(None, store, &mut store_writer);
            }
        },
    };

    if let Err(e) = master {
        println!("{e}");
        process::exit_safe(None, store, &mut store_writer);
    } else {
        println!("Login successful!");
    }

    let mut master = master.unwrap();

    while master.len() < 32 {
        master.push(0);
    }

    assert_eq!(master.len(), 32, "Key length is not 32 bytes!");

    println!(
        r"
    -------------------------------
    Commands:
    add <name> <username> <password>        -- add entry to store
    generate <name> <username>              -- generate password for entry and add to store
    get <name>                              -- get entry from store
    rm <name>                               -- remove entry from store
    list                                    -- list all entries
    exit                                    -- exit program (DO NOT USE CTRL+C)
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
            Some("add") => process::add_cmd(&mut args, &master, &mut store),

            Some("generate") => process::generate_cmd(&mut args, &master, &mut store),

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

                let entry = Entry::decrypt(entry_cipher.1, &master).expect("Decryption failed!");

                let username = entry.username.unwrap();
                let password = entry.password;

                let username = String::from_utf8(username).unwrap();
                let password = String::from_utf8(password).unwrap();

                println!("Name: {name}");
                println!("Username: {username}");
                println!("Password: {password}");
            }

            Some("rm") => process::rm_cmd(args, &mut store),

            Some("list") => process::list_cmd(&store),

            Some("exit") => process::exit_safe(None, store, &mut store_writer),
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

fn prompt_new_master_password() -> Result<Vec<u8>, Box<dyn Error>> {
    println!("Set master password (no longer than 28 characters): ");
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

fn prompt_login(master_pass: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
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

fn is_empty(input: &File) -> bool {
    let metadata = input.metadata().unwrap();
    metadata.len() == 0
}
