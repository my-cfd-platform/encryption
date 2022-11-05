pub struct AesKey {
    pub key: [u8; 32],
    pub iv: [u8; 16],
}

impl AesKey {
    pub fn new(key: &[u8]) -> AesKey {
        if key.len() != 48 {
            panic!("AesKey: key must be 48 bytes");
        }

        let mut aes_key = AesKey {
            key: [0; 32],
            iv: [0; 16],
        };
        aes_key.key.copy_from_slice(&key[..32]);
        aes_key.iv.copy_from_slice(&key[32..]);
        aes_key
    }

    pub fn get_cipher(&self) -> libaes::Cipher {
        libaes::Cipher::new_256(&self.key)
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        let cipher = self.get_cipher();
        cipher.cbc_encrypt(&self.iv, data)
    }

    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = self.get_cipher();

        let result = std::panic::catch_unwind(|| cipher.cbc_decrypt(&self.iv, data));
        match result {
            Ok(result) => Ok(result),
            Err(err) => Err(format!("AesKey: decryption failed: {:?}", err)),
        }
    }
}

#[cfg(test)]
mod test {

    use super::AesKey;

    #[test]
    pub fn encrypt() {
        let my_key = b"This is the key!This is the key!This is 16 bytes";

        let plaintext = b"My Phrase";
        let key = AesKey::new(my_key);

        // Encryption
        let encrypted = key.encrypt(plaintext);

        // Decryption
        let decrypted = key.decrypt(&encrypted[..]).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    pub fn encrypt_with_error() {
        let my_key = b"This is the key!This is the key!This is 16 bytes";

        let plaintext = b"My Phrase";
        let key = AesKey::new(my_key);

        // Encryption
        let encrypted = key.encrypt(plaintext);

        // Decryption
        let decrypted = key.decrypt(&encrypted[..5]);

        assert!(decrypted.is_err());
    }

    #[test]
    pub fn encrypt_two_times_the_same_result() {
        let my_key = b"This is the key!This is the key!This is 16 bytes";

        let plaintext = b"My Phrase";
        let key = AesKey::new(my_key);

        // Encryption
        let encrypted1 = key.encrypt(plaintext);

        let encrypted2 = key.encrypt(plaintext);

        assert_eq!(encrypted1, encrypted2);
    }
}
