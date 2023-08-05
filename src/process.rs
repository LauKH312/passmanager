use std::{fs::File, process::exit};

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
    let entry = Entry::from_unencrypted(Some(username), &password.as_bytes().to_vec(), master);
    store.entries.insert(name.to_string(), entry);
    println!("Entry added!");

    // let entry = store::Entry {
    //     username: Some(encrypt(username)),
    //     pass_hash: encrypt(password),
    // };

    // serde_json::to_writer(&store_file, &mut store)?;
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

    // let entry = store::Entry {
    //     username: Some(encrypt(username)),
    //     password: encrypt(&password),
    // };
}

pub fn rm_cmd(mut args: std::str::SplitWhitespace<'_>, store: &mut Store) {
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
