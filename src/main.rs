use std::{error::Error, fs::File, path::Path, process::exit};

use crate::store::Store;

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
        Some(master_hash) => process::prompt_login(master_hash),

        // Handle case where master password is not set.
        // Matches if user has properly set the new master password.
        None => match process::prompt_new_master_password() {
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

            Some("get") => process::get_cmd(&mut args, &store, &master),

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

fn is_empty(input: &File) -> bool {
    let metadata = input.metadata().unwrap();
    metadata.len() == 0
}
