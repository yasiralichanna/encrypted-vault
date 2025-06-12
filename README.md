# Encrypted File Vault

A secure CLI vault for encrypting/decrypting files with AES-256 encryption.

## Features

- File encryption/decryption with AES-256
- Password-based or keyfile authentication
- Secure file shredding (overwrite before delete)
- Cross-platform (Windows, macOS, Linux)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yasiralichanna/encrypted-vault.git
   cd encrypted-vault
   ```
   Usage
Encrypt a file
Using password:

```bash
python vault.py encrypt secret.txt -p "yourpassword"
```
Using keyfile:

```bash
python vault.py encrypt secret.txt -k mykey.key
```
Decrypt a file
Using password:

```bash
python vault.py decrypt secret.txt.enc -p "yourpassword"
```
Using keyfile:

```bash
python vault.py decrypt secret.txt.enc -k mykey.key
```
Securely delete a file
```bash
python vault.py shred sensitive.txt
```
Generate a new keyfile
```bash
python vault.py keygen -o mykey.key
```
Security Notes
Always keep backups of your keyfiles/passwords

For maximum security, use both password and keyfile

Secure delete doesn't work on SSDs as effectively as on HDDs