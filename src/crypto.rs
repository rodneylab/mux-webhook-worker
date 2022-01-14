use hmac::{Mac, SimpleHmac};
use sha2::Sha256;

type HmacSha256 = SimpleHmac<Sha256>;

#[allow(dead_code)]
pub fn hmac_sha_256_sign(key: &[u8], message: &[u8]) -> Vec<u8> {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(val) => val,
        Err(_) => panic!("Error parsing HMAC_SHA256 key"),
    };
    mac.update(message);
    let result = mac.finalize().into_bytes();
    result.to_vec()
}

pub fn hmac_sha_256_verify(key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(val) => val,
        Err(_) => panic!("Error parsing HMAC_SHA256 key"),
    };
    mac.update(message);
    let result = mac.finalize().into_bytes();
    result.as_slice() == signature
}

#[cfg(test)]
mod tests {
    use crate::crypto::{hmac_sha_256_sign, hmac_sha_256_verify};

    #[test]
    pub fn test_hmac_sha_256_sign() {
        let message = "Test string".as_bytes();
        let key = "secret_key".as_bytes();
        let signature =
            hex::decode("3008e62f1f6ef4ec411c5e6b4a4dfc32266e49866d9962c68d0abd489bac83da")
                .unwrap();
        assert_eq!(hmac_sha_256_sign(key, message), signature);
    }

    #[test]
    pub fn test_hmac_sha_256_verify() {
        let message = "Test string".as_bytes();
        let key = "secret_key".as_bytes();
        let signature =
            hex::decode("3008e62f1f6ef4ec411c5e6b4a4dfc32266e49866d9962c68d0abd489bac83da")
                .unwrap();
        assert!(hmac_sha_256_verify(key, message, &signature));
    }
}
