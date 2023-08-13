# Passmanager V0.1

![Passmanager](display.png)

## Description

Short project implementing an ulta simple password manager in Rust with the following features:

- Password hashing with SHA2 and salt
- Password encryption with AES256-GCM
- Serilized password storage using Serde-JSON.
- Password generation

## Motivations

I wanted to familiarize myself with the cryptography ecosystem in Rust, aswell as general application of cryptographic algorithms. The experience gained is relevant in my portfolio to strengthen my fullstack developer profile.
_This manager is **not** intended for real world use._

## Omissions

Some important features are omitted from this project, as they are not the focus of the project. Most of these are relatively minor or trivial additions. The omissions include:

- No zeroization of sensitive data
- No password strength checking
- Password length not configurable.
