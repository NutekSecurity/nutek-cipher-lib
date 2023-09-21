# nutek-cipher-lib

a library for encrypting and decrypting text using the AES-GCM-SIV cipher

## Installation

```bash
cargo add nutek-cipher-lib
```

## Usage

```rust
use nutek_cipher_lib::aes_gcm_siv::encrypt;
use nutek_cipher_lib::aes_gcm_siv::decrypt;

fn main() {
    let key = b"0123456789abcdef0123456789abcdef";
    let nonce = b"123456123456";
    let plaintext = b"Hello, world!";
    let ciphertext = encrypt(plaintext, nonce, key);
    let decrypted = decrypt(key, nonce, &ciphertext).unwrap();
    assert_eq!(plaintext, decrypted);
}
```

## License

non-commercial use only, see [LICENSE](./LICENSE)