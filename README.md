# SeedVault

Secure offline encryption tool for cryptocurrency seed phrases (12/15/18/21/24 words).

## Features

- ✅ ChaCha20-Poly1305 authenticated encryption
- ✅ Argon2id key derivation (GPU-resistant)
- ✅ Supports BIP39 standard (12-24 words)
- ✅ Multiple input methods (paste/file/interactive)
- ✅ Secure memory handling with zeroization
- ✅ Offline operation (no network required)

## Security

⚠️ **IMPORTANT DISCLAIMERS**

- **This tool has NOT been professionally audited**
- **Use at your own risk** - always verify the code yourself
- **THIS IS NOT A REPLACEMENT FOR PROPER BACKUPS**

Always maintain multiple unencrypted backups of your seed phrase in physically secure locations (metal plates, paper in safes, etc.). This tool provides an *additional* layer of encrypted storage, not a replacement.

### Security Considerations

- **Password strength is critical** - Use a strong, unique password (12+ characters recommended)
- **No password recovery** - If you forget your password, your seed phrase is permanently lost
- **Encrypted file storage** - The encrypted file is only as secure as your system and password
- **Memory safety** - Rust provides memory safety, but sensitive data may still exist in RAM
- **Offline only** - Never use this tool on internet-connected machines if maximum security is required

### Cryptography Used

- **Encryption**: ChaCha20-Poly1305 (authenticated encryption)
- **Key derivation**: Argon2id with 64MB memory, 3 iterations (GPU-resistant)
- **Random data**: OS-provided cryptographically secure random number generator

## Usage
```bash
./seedvault
```

Choose option 1 to encrypt, option 2 to decrypt.

## Building
```bash
cargo build --release
```

## License

MIT OR Apache-2.0
