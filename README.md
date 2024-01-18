# Passmanager V0.1

![Passmanager](display.png)

> A simple CLI password manager written in Rust.

## Description

Short project implementing a password manager in Rust with the following features:

- Master password hashing with SHA2 and salt
- Password encryption with AES256-GCM
- Serialized password storage using Serde-JSON.
- Password generation

Whilst not being production ready, it provides some baseline of security for password storage. The password manager is not intended for real-world use, instead it is a learning project:

## Motivations

I wanted to familiarize myself with the cryptography ecosystem in Rust, as well as the general application of cryptographic algorithms. The experience gained is relevant to strengthen my full-stack developer profile.
_This manager is **not** intended for real-world use._

## Omissions

Some important features are omitted from this project, as they are not the focus of the project. Most are relatively minor or trivial additions. Omissions include:

- No password strength checking
- Password length not configurable.

## Building

### Requirements

Rust and Cargo are required to build the project. The project is built using the following versions (although older versions will likely work):

- Rustc: 1.73.0
- Cargo: 1.73.0

Make sure to have an internet connection for the first build, as cargo will download the dependencies.

### Steps

1. Clone the repository

   ```bash
       git clone https://github.com/LauKH312/passmanager.git
   ```

2. Build the project

   ```bash
       cargo build --release
   ```

The executable can now be fount at `{root}/target/release/passmanager.{?}`.
File extension depends on the platform.

## Usage

### Subcommands

`add <name> <username> <password>`

Adds a password, that can be retrieved later using the {name}. Typing a username is optional.

`generate <name> <username>`

Generates a password, and adds it to the password manager. The password can be retrieved later using the {name}. Typing a username is optional.

`get <name>`

Gets the password associated with {name}.

`rm <name>`

Removes the password associated with {name}.

`list`

Lists all the passwords in the password manager.

`exit`

Exits the password manager.

### Example

```bash
    $ passmanager
    > generate github laukh312
    Generated password: [5f2a8b8c]
    > get github
    Name: github
    Username: laukh312
    Password: [5f2a8b8c]
    > rm github
    > list
    > exit
```
