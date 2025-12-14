# SeedVault

Secure offline encryption tool for BIP39 and SLIP39 seed phrases.

## Features

- ✅ ChaCha20-Poly1305 authenticated encryption
- ✅ Argon2id key derivation (GPU-resistant)
- ✅ Supports BIP39 (12/15/18/21/24 words) and SLIP39 (20/33 words)
- ✅ Multiple input methods (paste/file/interactive)
- ✅ Paranoid mode with screen clearing
- ✅ Restrictive file permissions (600 on Unix)
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
- **Memory safety** - Rust provides memory safety, but sensitive data (seed phrases, passwords) remain in RAM until the process exits or memory is reused. Only run on trusted machines.
- **Offline only** - Never use this tool on internet-connected machines if maximum security is required

### Terminal History Warning

⚠️ **CRITICAL**: This tool displays seed phrases in plaintext on your terminal.

**After using this tool, clear your terminal history**:
- Bash: `history -c && rm ~/.bash_history`
- Zsh: `history -c && rm ~/.zsh_history`

**Better yet**: Run this tool on an air-gapped machine that doesn't save history.

**Use the `--paranoid` flag**: When decrypting, use `./seedvault decrypt --paranoid <file>` to automatically clear the screen after viewing your seed phrase.

### Cryptography Used

- **Encryption**: ChaCha20-Poly1305 (authenticated encryption with 128-bit security)
- **Key derivation**: Argon2id with 64MB memory, 3 iterations, 4 parallelism (GPU-resistant)
- **Random data**: OS-provided cryptographically secure random number generator (OsRng)

### File Format

Encrypted files use the following format:
```
[4 bytes: magic "SVT\x01"] [22+ bytes: base64 salt] [1 byte: newline] [12 bytes: nonce] [variable: ciphertext + 16-byte auth tag]
```

## Usage

### Interactive Mode
```bash
./seedvault
```
Choose option 1 to encrypt, option 2 to decrypt.

### Command Line Mode
```bash
# Decrypt a file
./seedvault decrypt seed_phrase.enc

# Decrypt with paranoid mode (clears screen after viewing)
./seedvault decrypt --paranoid seed_phrase.enc
```

## Building
```bash
cargo build --release
```

## License

MIT OR Apache-2.0
