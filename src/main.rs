use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHasher, SaltString},
};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use std::fs;
use std::io::{self, Write};
use std::path::Path;

const ENCRYPTED_FILE: &str = "seed_phrase.enc";
const VALID_WORD_COUNTS: &[usize] = &[12, 15, 18, 20, 21, 24, 33];
const MAX_FILE_SIZE: u64 = 10_000;
const FILE_MAGIC: &[u8] = b"SVT\x01";
const NONCE_SIZE: usize = 12;
const MIN_ENCRYPTED_FILE_SIZE: usize = 55; // magic(4) + min_salt(22) + newline(1) + nonce(12) + min_ciphertext(16)
const MIN_CIPHERTEXT_SIZE: usize = 16; // Poly1305 authentication tag

enum RunMode {
    Interactive,
    DecryptFile { path: String, paranoid: bool },
}

fn main() {
    let mode = parse_args();

    match mode {
        RunMode::Interactive => run_interactive_mode(),
        RunMode::DecryptFile { path, paranoid } => {
            if let Err(e) = decrypt_seed_phrase(Some(&path), paranoid) {
                eprintln!("\nError: {}", e);
                std::process::exit(1);
            }
        }
    }
}

fn parse_args() -> RunMode {
    let args: Vec<String> = std::env::args().collect();

    match args.len() {
        1 => RunMode::Interactive,
        3 if args[1] == "decrypt" => RunMode::DecryptFile {
            path: args[2].clone(),
            paranoid: false
        },
        4 if args[1] == "decrypt" && args[2] == "--paranoid" => RunMode::DecryptFile {
            path: args[3].clone(),
            paranoid: true
        },
        4 if args[1] == "--paranoid" && args[2] == "decrypt" => RunMode::DecryptFile {
            path: args[3].clone(),
            paranoid: true
        },
        _ => {
            eprintln!("Usage:");
            eprintln!("  {} (interactive mode)", args[0]);
            eprintln!("  {} decrypt <file_path>", args[0]);
            eprintln!("  {} decrypt --paranoid <file_path>", args[0]);
            std::process::exit(1);
        }
    }
}

fn run_interactive_mode() {
    println!("Seed Phrase Vault\n");
    println!("1. Encrypt seed phrase");
    println!("2. Decrypt seed phrase");
    print!("\nChoice: ");
    let _ = io::stdout().flush();

    let mut choice = String::new();
    if io::stdin().read_line(&mut choice).is_err() {
        eprintln!("Failed to read input");
        return;
    }

    match choice.trim() {
        "1" => {
            if let Err(e) = encrypt_seed_phrase() {
                eprintln!("\nError: {}", e);
            }
        }
        "2" => {
            if let Err(e) = decrypt_interactive(false) {
                eprintln!("\nError: {}", e);
            }
        }
        _ => println!("Invalid choice"),
    }
}

fn encrypt_seed_phrase() -> Result<(), String> {
    // Get seed phrase using selected input method
    let words = get_seed_phrase_input()?;

    // Validate word count
    if !VALID_WORD_COUNTS.contains(&words.len()) {
        return Err(format!(
            "Invalid word count: {}. Must be 12, 15, 18, 20, 21, 24, or 33 words.",
            words.len()
        ));
    }

    // Show confirmation
    println!("\nYour seed phrase ({} words):", words.len());
    for (i, word) in words.iter().enumerate() {
        println!("{}. {}", i + 1, word);
    }

    print!("\nIs this correct? (yes/no): ");
    let _ = io::stdout().flush();
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm)
        .map_err(|e| format!("Failed to read input: {}", e))?;

    if confirm.trim().to_lowercase() != "yes" {
        return Err("Aborted by user".to_string());
    }

    // Check if file exists
    if Path::new(ENCRYPTED_FILE).exists() {
        print!("\nFile '{}' already exists. Overwrite? (yes/no): ", ENCRYPTED_FILE);
        let _ = io::stdout().flush();
        let mut overwrite = String::new();
        io::stdin().read_line(&mut overwrite)
            .map_err(|e| format!("Failed to read input: {}", e))?;
        if overwrite.trim().to_lowercase() != "yes" {
            return Err("Aborted to prevent overwrite".to_string());
        }
    }

    // Get password
    let password = rpassword::prompt_password("\nEnter encryption password: ")
        .map_err(|e| format!("Failed to read password: {}", e))?;

    if password.is_empty() {
        return Err("Password cannot be empty".to_string());
    }

    let password_confirm = rpassword::prompt_password("Confirm password: ")
        .map_err(|e| format!("Failed to read password: {}", e))?;

    if password != password_confirm {
        return Err("Passwords don't match".to_string());
    }

    // Simple password strength warning
    if password.len() < 12 {
        println!("\nWarning: Password is short. Consider using 12+ characters.");
    }

    // Generate salt and derive key
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(65536, 3, 4, None)
        .map_err(|e| format!("Failed to create Argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash password: {}", e))?;

    let key_bytes = password_hash
        .hash
        .ok_or("Failed to extract key from hash")?;
    let key = key_bytes.as_bytes();

    // Verify key length before creating cipher
    if key.len() < 32 {
        return Err(format!("Key derivation produced insufficient bytes: got {}, need 32", key.len()));
    }

    // Create cipher and encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&key[..32])
        .map_err(|e| format!("Invalid key length: {}", e))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = words.join(" ");
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Format: magic || salt || nonce || ciphertext
    let mut output = Vec::new();
    output.extend_from_slice(FILE_MAGIC);
    output.extend_from_slice(salt.as_str().as_bytes());
    output.push(b'\n');
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    // Save to file
    fs::write(ENCRYPTED_FILE, &output)
        .map_err(|e| format!("Failed to write file: {}", e))?;

    // Set restrictive permissions on Unix systems
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(ENCRYPTED_FILE, fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("Failed to set file permissions: {}", e))?;
    }

    println!("\nSuccess! Seed phrase encrypted and saved to '{}'", ENCRYPTED_FILE);
    println!("Remember your password - there's no recovery option.\n");

    Ok(())
}

fn decrypt_interactive(paranoid: bool) -> Result<(), String> {
    decrypt_seed_phrase(None, paranoid)
}

fn validate_and_canonicalize_path(path_str: &str) -> Result<std::path::PathBuf, String> {
    let path = Path::new(path_str);

    let canonical = path
        .canonicalize()
        .map_err(|_| format!("File not found: {}", path_str))?;

    let metadata = fs::metadata(&canonical)
        .map_err(|_| format!("Cannot access file: {}", path_str))?;

    if !metadata.is_file() {
        return Err(format!("Path is not a regular file: {}", path_str));
    }

    if metadata.len() > MAX_FILE_SIZE {
        return Err("Encrypted file too large".to_string());
    }

    Ok(canonical)
}

fn prompt_for_custom_file_path() -> Result<std::path::PathBuf, String> {
    println!("\nDefault file '{}' not found.", ENCRYPTED_FILE);
    print!("Enter encrypted file path: ");
    let _ = io::stdout().flush();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Failed to read input: {}", e))?;

    let path_str = input.trim().trim_matches('"').trim_matches('\'');
    validate_and_canonicalize_path(path_str)
}

fn decrypt_seed_phrase(file_path: Option<&str>, paranoid: bool) -> Result<(), String> {
    // Determine which file to decrypt
    let path_to_decrypt = match file_path {
        Some(path) => validate_and_canonicalize_path(path)?,
        None => {
            if Path::new(ENCRYPTED_FILE).exists() {
                validate_and_canonicalize_path(ENCRYPTED_FILE)?
            } else {
                prompt_for_custom_file_path()?
            }
        }
    };

    // Check file size before reading
    let metadata = fs::metadata(&path_to_decrypt)
        .map_err(|_| format!("Could not access file '{}'", path_to_decrypt.display()))?;

    if metadata.len() > MAX_FILE_SIZE {
        return Err("Encrypted file too large".to_string());
    }

    // Read encrypted file
    let data = fs::read(&path_to_decrypt)
        .map_err(|_| format!("Could not read file '{}'", path_to_decrypt.display()))?;

    if data.len() < MIN_ENCRYPTED_FILE_SIZE {
        return Err("File appears corrupted (too small)".to_string());
    }

    // Validate format
    if !data.starts_with(FILE_MAGIC) {
        return Err("Invalid file format".to_string());
    }

    // Parse file
    let newline_pos = data[4..]
        .iter()
        .position(|&b| b == b'\n')
        .ok_or("Invalid file format")?;

    // Verify we have enough data for nonce + minimum ciphertext
    if data.len() < 4 + newline_pos + 1 + NONCE_SIZE + MIN_CIPHERTEXT_SIZE {
        return Err("File appears corrupted (insufficient data)".to_string());
    }

    let salt_str = std::str::from_utf8(&data[4..4 + newline_pos])
        .map_err(|_| "Invalid salt encoding")?;
    let nonce_start = 4 + newline_pos + 1;
    let nonce_bytes = &data[nonce_start..nonce_start + NONCE_SIZE];
    let ciphertext = &data[nonce_start + NONCE_SIZE..];

    // Verify minimum ciphertext size (must include 16-byte auth tag)
    if ciphertext.len() < MIN_CIPHERTEXT_SIZE {
        return Err("File appears corrupted (ciphertext too small)".to_string());
    }

    // Get password and derive key
    let password = rpassword::prompt_password("\nEnter decryption password: ")
        .map_err(|e| format!("Failed to read password: {}", e))?;

    if password.is_empty() {
        return Err("Password cannot be empty".to_string());
    }

    let salt = SaltString::from_b64(salt_str).map_err(|_| "Invalid salt format")?;
    let params = Params::new(65536, 3, 4, None)
        .map_err(|e| format!("Failed to create Argon2 params: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("Failed to hash password: {}", e))?;

    let key_bytes = password_hash
        .hash
        .ok_or("Failed to extract key from hash")?;
    let key = key_bytes.as_bytes();

    // Verify key length before creating cipher
    if key.len() < 32 {
        return Err(format!("Key derivation produced insufficient bytes: got {}, need 32", key.len()));
    }

    // Decrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&key[..32])
        .map_err(|e| format!("Invalid key length: {}", e))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed! Incorrect password or corrupted file.".to_string())?;

    let seed_phrase = String::from_utf8(plaintext_bytes)
        .map_err(|_| "Decrypted data is not valid UTF-8")?;

    let words: Vec<&str> = seed_phrase.split_whitespace().collect();

    if !VALID_WORD_COUNTS.contains(&words.len()) {
        return Err(format!(
            "Invalid seed phrase: got {} words",
            words.len()
        ));
    }

    // Display result
    println!("\nDecryption successful!\n");
    println!("Your seed phrase ({} words):\n", words.len());
    for (i, word) in words.iter().enumerate() {
        println!("{}. {}", i + 1, word);
    }
    println!();

    // Paranoid mode: clear screen after user confirms they've saved the seed phrase
    if paranoid {
        print!("\nPress Enter to clear screen...");
        let _ = io::stdout().flush();
        let mut buf = String::new();
        if io::stdin().read_line(&mut buf).is_err() {
            eprintln!("Warning: Failed to read input, screen not cleared!");
            return Ok(());
        }
        print!("\x1B[2J\x1B[1;1H"); // ANSI escape codes to clear screen
        let _ = io::stdout().flush();
    }

    Ok(())
}

fn get_seed_phrase_input() -> Result<Vec<String>, String> {
    println!("\nChoose input method:");
    println!("1. Paste all words");
    println!("2. Read from file");
    println!("3. Enter one word at a time");
    print!("\nChoice: ");
    let _ = io::stdout().flush();

    let mut method_choice = String::new();
    io::stdin().read_line(&mut method_choice)
        .map_err(|e| format!("Failed to read input: {}", e))?;

    match method_choice.trim() {
        "1" => read_words_paste(),
        "2" => read_words_from_file(),
        "3" => read_words_interactive(),
        _ => Err("Invalid choice".to_string()),
    }
}

fn read_words_paste() -> Result<Vec<String>, String> {
    println!("\nPaste your seed phrase (words separated by spaces):");
    print!("> ");
    let _ = io::stdout().flush();

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("Failed to read input: {}", e))?;

    let words: Vec<String> = input.split_whitespace().map(|s| s.to_lowercase()).collect();

    if words.is_empty() {
        return Err("No words entered".to_string());
    }

    Ok(words)
}

fn read_words_from_file() -> Result<Vec<String>, String> {
    print!("\nEnter file path: ");
    let _ = io::stdout().flush();

    let mut path = String::new();
    io::stdin()
        .read_line(&mut path)
        .map_err(|e| format!("Failed to read path: {}", e))?;
    let path = path.trim().trim_matches('"').trim_matches('\'');

    // Safety: Check file size before reading
    let metadata = fs::metadata(path)
        .map_err(|_| "File not found")?;

    if metadata.len() > MAX_FILE_SIZE {
        return Err("File too large (max 10KB)".to_string());
    }

    let contents = fs::read_to_string(path)
        .map_err(|_| "Failed to read file")?;

    let words: Vec<String> = contents
        .split_whitespace()
        .map(|s| s.to_lowercase())
        .collect();

    if words.is_empty() {
        return Err("File is empty".to_string());
    }

    Ok(words)
}

fn read_words_interactive() -> Result<Vec<String>, String> {
    print!("\nHow many words? (12, 15, 18, 20, 21, 24, or 33): ");
    let _ = io::stdout().flush();

    let mut count_str = String::new();
    io::stdin()
        .read_line(&mut count_str)
        .map_err(|e| format!("Failed to read input: {}", e))?;

    let count: usize = count_str
        .trim()
        .parse()
        .map_err(|_| "Invalid number".to_string())?;

    if !VALID_WORD_COUNTS.contains(&count) {
        return Err(format!("Invalid word count: {}", count));
    }

    println!("\nEnter your {} words:", count);
    let mut words = Vec::new();
    for i in 1..=count {
        print!("Word {}: ", i);
        let _ = io::stdout().flush();
        let mut word = String::new();
        io::stdin()
            .read_line(&mut word)
            .map_err(|e| format!("Failed to read word: {}", e))?;
        let trimmed = word.trim().to_lowercase();
        if trimmed.is_empty() {
            return Err(format!("Word {} cannot be empty", i));
        }
        words.push(trimmed);
    }

    Ok(words)
}
