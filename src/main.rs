use crate::store::Store;
use std::{fs::File, path::Path};

mod crypto;
mod process;
mod store;

const STORE_PATH: &str = r"C:\Temp\cpasswordstore\store.json";
const BACKUP_PATH: &str = r"C:\Temp\cpasswordstore\store-bac.json";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    ctrlc::set_handler(|| {
        println!("To exit safely, type 'exit'.");

        // TODO: Allow user to exit safely with Ctrl+C
    })?;

    if !Path::new(STORE_PATH).exists() {
        println!("Store does not exist, creating store file...");
        File::create(STORE_PATH)?;
        println!("Store file created!");
    }

    let store_file = File::open(STORE_PATH)?;

    // if store is empty, create new store or restore from backup
    if store::is_empty(&store_file) {
        match Path::new(BACKUP_PATH).exists() {
            true => match store::filecpy(STORE_PATH, BACKUP_PATH) {
                Ok(_) => println!("Restored from backup!"),
                Err(e) => println!("Restoring backup failed! {e}"),
            },

            false => match Store::create() {
                Ok(_) => println!("Created new store!"),
                Err(e) => println!("Creating new store failed! {e}"),
            },
        };
        std::process::exit(0);
    }

    let mut store: Store = serde_json::from_reader(&store_file)?;

    {
        // Create backup, later File::create() will overwrite existing file
        let backup = File::create(BACKUP_PATH)?;
        serde_json::to_writer(&backup, &store)?;
    }

    let mut store_writer = File::create(STORE_PATH)?;

    // if store is not empty, prompt login, and hashes provided pass.
    let master = match store.master.as_ref() {
        Some(master_hash) => {
            process::prompt_login(master_hash, store.master_salt.as_ref().unwrap())
        }

        // Handle case where master password is not set.
        // Matches if user has properly set the new master password.
        None => match process::prompt_new_master_password() {
            Ok(master) => {
                let salt = crypto::generate_salt(master.len());
                let master_hash = crypto::salt_and_hash(&master, &salt);

                store.master_salt = Some(salt.to_vec());
                store.master = Some(master_hash);

                println!("Successfully created new key!");
                Ok(master)
            }
            Err(e) => {
                println!("{e}");
                process::exit_safe(None, store, &mut store_writer, None);
            }
        },
    };

    process::clear_screen();

    if let Err(e) = master {
        eprintln!("{e}");
        process::exit_safe(None, store, &mut store_writer, None);
    }

    println!("Passmanager v0.1.0");

    let mut master = master?;

    while master.len() < 32 {
        master.push(0);
    }

    // Assert length is not above 32 bytes
    assert_eq!(master.len(), 32, "Key length is not 32 bytes");

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
            Some("exit") => process::exit_safe(None, store, &mut store_writer, Some(master)),
            _ => {
                eprintln!("Invalid command");
            }
        }
    }
}
