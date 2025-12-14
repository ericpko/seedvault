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
const VALID_WORD_COUNTS: &[usize] = &[12, 15, 18, 21, 24];
const MAX_FILE_SIZE: u64 = 10_000;

fn main() {
    println!("Seed Phrase Vault\n");
    println!("1. Encrypt seed phrase");
    println!("2. Decrypt seed phrase");
    print!("\nChoice: ");
    io::stdout().flush().unwrap();

    let mut choice = String::new();
    io::stdin().read_line(&mut choice).unwrap();

    match choice.trim() {
        "1" => {
            if let Err(e) = encrypt_seed_phrase() {
                eprintln!("\nError: {}", e);
            }
        }
        "2" => {
            if let Err(e) = decrypt_seed_phrase() {
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
            "Invalid word count: {}. Must be 12, 15, 18, 21, or 24 words.",
            words.len()
        ));
    }

    // Show confirmation
    println!("\nYour seed phrase ({} words):", words.len());
    for (i, word) in words.iter().enumerate() {
        println!("{}. {}", i + 1, word);
    }

    print!("\nIs this correct? (yes/no): ");
    io::stdout().flush().unwrap();
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm).unwrap();

    if confirm.trim().to_lowercase() != "yes" {
        return Err("Aborted by user".to_string());
    }

    // Check if file exists
    if Path::new(ENCRYPTED_FILE).exists() {
        print!("\nFile '{}' already exists. Overwrite? (yes/no): ", ENCRYPTED_FILE);
        io::stdout().flush().unwrap();
        let mut overwrite = String::new();
        io::stdin().read_line(&mut overwrite).unwrap();
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

    // Create cipher and encrypt
    let cipher = ChaCha20Poly1305::new_from_slice(&key[..32])
        .map_err(|e| format!("Invalid key length: {}", e))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = words.join(" ");
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Format: magic || salt || nonce || ciphertext
    let mut output = Vec::new();
    output.extend_from_slice(b"SVT\x01");
    output.extend_from_slice(salt.as_str().as_bytes());
    output.push(b'\n');
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    // Save to file
    fs::write(ENCRYPTED_FILE, &output)
        .map_err(|e| format!("Failed to write file: {}", e))?;

    println!("\nSuccess! Seed phrase encrypted and saved to '{}'", ENCRYPTED_FILE);
    println!("Remember your password - there's no recovery option.\n");

    Ok(())
}

fn decrypt_seed_phrase() -> Result<(), String> {
    // Check file size before reading
    let metadata = fs::metadata(ENCRYPTED_FILE)
        .map_err(|_| format!("Could not find file '{}'", ENCRYPTED_FILE))?;

    if metadata.len() > MAX_FILE_SIZE {
        return Err("Encrypted file too large".to_string());
    }

    // Read encrypted file
    let data = fs::read(ENCRYPTED_FILE)
        .map_err(|_| format!("Could not read file '{}'", ENCRYPTED_FILE))?;

    if data.len() < 54 {
        return Err("File appears corrupted (too small)".to_string());
    }

    // Validate format
    if !data.starts_with(b"SVT\x01") {
        return Err("Invalid file format".to_string());
    }

    // Parse file
    let newline_pos = data[4..]
        .iter()
        .position(|&b| b == b'\n')
        .ok_or("Invalid file format")?;

    if data.len() < 4 + newline_pos + 1 + 12 {
        return Err("File appears corrupted".to_string());
    }

    let salt_str = std::str::from_utf8(&data[4..4 + newline_pos])
        .map_err(|_| "Invalid salt encoding")?;
    let nonce_start = 4 + newline_pos + 1;
    let nonce_bytes = &data[nonce_start..nonce_start + 12];
    let ciphertext = &data[nonce_start + 12..];

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

    Ok(())
}

fn get_seed_phrase_input() -> Result<Vec<String>, String> {
    println!("\nChoose input method:");
    println!("1. Paste all words");
    println!("2. Read from file");
    println!("3. Enter one word at a time");
    print!("\nChoice: ");
    io::stdout().flush().unwrap();

    let mut method_choice = String::new();
    io::stdin().read_line(&mut method_choice).unwrap();

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
    io::stdout().flush().unwrap();

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
    io::stdout().flush().unwrap();

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
    print!("\nHow many words? (12, 15, 18, 21, or 24): ");
    io::stdout().flush().unwrap();

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
        io::stdout().flush().unwrap();
        let mut word = String::new();
        io::stdin()
            .read_line(&mut word)
            .map_err(|e| format!("Failed to read word: {}", e))?;
        words.push(word.trim().to_lowercase());
    }

    Ok(words)
}
