use std::{fs::File, path::Path};

use crate::store::Store;

mod crypto_utils;
mod process;
mod store;

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
    if store::is_empty(&store_file) {
        match Path::new(BACKUP_URL).exists() {
            true => match store::load_from_backup() {
                Ok(_) => println!("Restored from backup!"),
                Err(e) => println!("Restoring backup failed! {e}"),
            },

            false => match store::create() {
                Ok(_) => println!("Created new store!"),
                Err(e) => println!("Creating new store failed! {e}"),
            },
        };
        std::process::exit(0);
    }

    // load store
    let mut store: Store = serde_json::from_reader(&store_file)?;

    {
        // Create backup, later File::create() will overwrite existing file
        let backup = File::create(BACKUP_URL)?;
        serde_json::to_writer(&backup, &store)?;
    }

    // create write
    let mut store_writer = File::create(STORE_URL)?;

    // if store is not empty, prompt login, and hashes provided pass.
    let master = match store.master.as_ref() {
        Some(master_hash) => {
            process::prompt_login(master_hash, store.master_salt.as_ref().unwrap())
        }

        // Handle case where master password is not set.
        // Matches if user has properly set the new master password.
        None => match process::prompt_new_master_password() {
            Ok(master) => {
                let salt = crypto_utils::generate_salt(master.len());
                let master_hash = crypto_utils::hash_and_salt(&master, &salt);

                store.master_salt = Some(salt.to_vec());
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

    // clear screen
    print!("\x1B[2J\x1B[1;1H");

    if let Err(e) = master {
        println!("{e}");
        process::exit_safe(None, store, &mut store_writer);
    } else {
        println!("Passmanager v0.1.0");
    }

    let mut master = master?;

    while master.len() < 32 {
        master.push(0);
    }

    assert_eq!(master.len(), 32, "Key length is not 32 bytes!");

    process::print_guide();

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
