# SeedVault

Secure offline encryption tool for BIP39 and SLIP39 seed phrases.

## Description

SeedVault allows you to encrypt your cryptocurrency seed phrases with a strong password, creating an encrypted file that can be safely stored in cloud storage platforms (Google Drive, Dropbox, iCloud, etc.) as a backup to your physical storage methods.

### Why Use SeedVault?

**The Problem**: You need backups of your seed phrase, but storing plaintext seed phrases in cloud storage is extremely dangerous. If your account is compromised or a cloud provider has a data breach, your funds are at risk.

**The Solution**: Encrypt your seed phrase with SeedVault before backing it up to the cloud. Even if someone gains access to the encrypted file, they cannot recover your seed phrase without your password.

### Typical Use Case

1. **Encrypt** your seed phrase on an offline/air-gapped computer using a strong password
2. **Store** the resulting encrypted file in multiple cloud storage platforms (Dropbox, Google Drive, etc.)
3. **Keep** your password separate and secure (memorize it, or store it separately from the encrypted file)
4. **Maintain** physical backups as your primary storage (metal plates, paper in safes)
5. **Use** cloud-stored encrypted files as an additional backup layer for disaster recovery

This way, you get the convenience and redundancy of cloud backups without the risk of exposing your seed phrase.

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
