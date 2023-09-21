pub mod aes_gcm_siv {
    extern crate aes_gcm_siv;
    use aes_gcm_siv::{
        aead::{Aead, KeyInit},
        Aes256GcmSiv, Nonce, Key  // Or `Aes128GcmSiv`
    };
    use aes_gcm_siv::aead::consts::U12;
    use aes_gcm_siv::aead::generic_array::GenericArray;

    /// Decrypts the given ciphertext with the given key and nonce.
    /// The key must be 32 bytes long and the nonce must be 12 bytes long.
    /// The plaintext is returned as an option vector of bytes.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use nutek_cipher_lib::aes_gcm_siv::decrypt;
    /// use nutek_cipher_lib::aes_gcm_siv::encrypt;
    /// 
    /// fn main() {
    ///     let ciphertext = encrypt(b"hello world", b"123456123456", b"12345678123456781234567812345678");
    ///     let plaintext = decrypt( b"12345678123456781234567812345678", b"123456123456", ciphertext).unwrap();
    ///     assert_eq!(plaintext, b"hello world");
    /// }
    /// ```
    /// 
    pub fn decrypt(key_slice: &[u8], nonce_slice: &[u8], ciphertext: Vec<u8>) -> Option<Vec<u8>> {
        let key = Key::<Aes256GcmSiv>::from_slice(key_slice);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce: &GenericArray<u8, U12> = Nonce::from_slice(nonce_slice);
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).ok()?;
        Some(plaintext)
    }

    /// Encrypts the given plaintext with the given key and nonce.
    /// The key must be 32 bytes long and the nonce must be 12 bytes long.
    /// The ciphertext is returned as a vector of bytes.
    /// 
    /// # Examples
    /// 
    /// ```
    /// use nutek_cipher_lib::aes_gcm_siv::encrypt;
    /// 
    /// fn main() {
    ///     encrypt(b"hello world", b"123456123456", b"12345678123456781234567812345678");
    /// }
    /// ```
    /// 
    pub fn encrypt(plaintext: &[u8], nonce_slice: &[u8], key_slice: &[u8]) -> Vec<u8> {
        let key = Key::<Aes256GcmSiv>::from_slice(key_slice);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce: &GenericArray<u8, U12> = Nonce::from_slice(nonce_slice);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).unwrap();
        if ciphertext.len() == 0 {
            panic!("❌ Ciphertext is empty");
        } else if ciphertext.len() > aes_gcm_siv::C_MAX.try_into().unwrap() {
            println!("❌ Ciphertext is too long");
        }
        ciphertext
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = b"12345678123456781234567812345678";
        let nonce = b"123456123456";
        let plaintext = b"hello world";

        // let ciphertext = encrypt(key, nonce, plaintext);
        let ciphertext = aes_gcm_siv::encrypt(plaintext, nonce, key);
        let decrypted_content = aes_gcm_siv::decrypt(key, nonce, ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted_content[..]);
    }
}