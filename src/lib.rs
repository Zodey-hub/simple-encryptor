use argon2::{password_hash::rand_core::RngCore, Argon2, RECOMMENDED_SALT_LEN};

use bitcode::{Decode, Encode};

use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};

use std::error::Error;

#[derive(Encode, Decode, PartialEq, Debug)]
struct EncryptedFile {
    data: Vec<u8>,
    salt: [u8; RECOMMENDED_SALT_LEN],
    nonce: [u8; 12],
}

pub fn encrypt(password: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut key = [0u8; 32];
    let mut salt = [0u8; RECOMMENDED_SALT_LEN];
    let mut nonce_buffer = [0u8; 12];

    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_buffer);

    Argon2::default()
        .hash_password_into(password, &salt, &mut key)
        .map_err(|err| err.to_string())?;

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let nonce = Nonce::from_slice(&nonce_buffer);

    let encrypted_data = cipher
        .encrypt(nonce, data)
        .map_err(|_| "Failed to encrypt!")?;

    let encrypted_file = EncryptedFile {
        data: encrypted_data,
        salt,
        nonce: nonce_buffer,
    };

    Ok(bitcode::encode(&encrypted_file))
}

pub fn decrypt(password: &[u8], data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let file: EncryptedFile = bitcode::decode(data)?;

    let mut key = [0u8; 32];

    Argon2::default()
        .hash_password_into(password, &file.salt, &mut key)
        .map_err(|err| err.to_string())?;

    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&key));
    let nonce = Nonce::from_slice(&file.nonce);

    let decrypted_data = cipher
        .decrypt(nonce, file.data.as_ref())
        .map_err(|_| "Failed to decrypt, invalid password!")?;

    Ok(decrypted_data)
}
