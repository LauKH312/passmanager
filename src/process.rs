use std::{error::Error, fs::File, process::exit};

use crate::{
    crypto_utils,
    store::{Entry, Store},
};

pub fn add_cmd(args: &mut std::str::SplitWhitespace<'_>, master: &Vec<u8>, store: &mut Store) {
    let name = match args.next() {
        Some(name) => name,
        None => {
            println!("Invalid command!");
            return;
        }
    };
    let username = match args.next() {
        Some(username) => username,
        None => {
            println!("Invalid command!");
            return;
        }
    };
    let username = username.as_bytes();
    let password = match args.next() {
        Some(password) => password,
        None => {
            println!("Invalid command!");
            return;
        }
    };
    let password = password.as_bytes();

    let entry = Entry::from_unencrypted(Some(username), &password.to_vec(), master);
    store.entries.insert(name.to_string(), entry);
    println!("Entry added!");
}

pub fn generate_cmd(args: &mut std::str::SplitWhitespace<'_>, master: &Vec<u8>, store: &mut Store) {
    let name = match args.next() {
        Some(name) => name,
        None => {
            println!("Invalid command!");
            return;
        }
    };
    let username = match args.next() {
        Some(username) => username,
        None => {
            println!("Invalid command!");
            return;
        }
    };
    let password = crypto_utils::random_text(32);
    println!("Generated password: [{password}]");
    let entry = Entry::from_unencrypted(
        Some(username.as_bytes()),
        &password.as_bytes().to_vec(),
        master,
    );
    store.entries.insert(name.to_string(), entry);
}

pub fn get_cmd(args: &mut std::str::SplitWhitespace<'_>, store: &Store, master: &Vec<u8>) {
    let name = match args.next() {
        Some(name) => name,
        None => {
            println!("Invalid command!");
            return;
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
            return;
        }
    };
    let entry = Entry::decrypt(entry_cipher.1, master).expect("Decryption failed!");
    let username = entry.username.unwrap();
    let password = entry.password;
    let username = String::from_utf8(username).unwrap();
    let password = String::from_utf8(password).unwrap();
    println!("Name: {name}");
    println!("Username: {username}");
    println!("Password: {password}");
}

pub fn rm_cmd(mut args: std::str::SplitWhitespace<'_>, store: &mut Store) {
    let name = args.next().unwrap();

    store.entries.remove(name);
    println!("Entry removed!");
}

pub fn list_cmd(store: &Store) {
    println!("vvvvvv");
    // print sorted list of entries
    let mut entries: Vec<&String> = store.entries.keys().collect();
    entries.sort();
    for entry in entries {
        println!("{entry}");
    }
}

pub fn exit_safe(dbg: Option<&str>, mut store: Store, store_file: &mut File) -> ! {
    serde_json::to_writer(store_file, &mut store).unwrap();

    // write eof
    // store_file.flush().unwrap();

    match dbg {
        Some(dbg) => panic!("{dbg}"),
        None => exit(0),
    }
}

pub fn prompt_new_master_password() -> Result<Vec<u8>, Box<dyn Error>> {
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

pub fn prompt_login(master_pass: &Vec<u8>) -> Result<Vec<u8>, Box<dyn Error>> {
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

