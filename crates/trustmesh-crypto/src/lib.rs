use core::fmt;

use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};

pub mod did;
pub use did::{CompositeResolver, DidError, DidKeyResolver, DidResolver, DidWebResolver};
pub use ed25519_dalek::Signature;

const MULTIKEY_MULTIBASE_PREFIX: char = 'z';
const ED25519_PUB_MULTIKEY_CODEC: [u8; 2] = [0xed, 0x01];
const ED25519_PUBLIC_KEY_LENGTH: usize = 32;
const ED25519_MULTIKEY_LENGTH: usize = ED25519_PUBLIC_KEY_LENGTH + ED25519_PUB_MULTIKEY_CODEC.len();

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    OsRandomness(String),
    InvalidPublicKey,
    InvalidMultikey,
    Verification,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::OsRandomness(msg) => write!(f, "failed to source OS randomness: {msg}"),
            Error::InvalidPublicKey => write!(f, "invalid Ed25519 public key"),
            Error::InvalidMultikey => write!(
                f,
                "invalid Multikey (expected multibase base58btc `z` encoding of an Ed25519 public key)"
            ),
            Error::Verification => write!(f, "signature verification failed"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone)]
pub struct SigningKey {
    inner: ed25519_dalek::SigningKey,
}

impl SigningKey {
    pub fn generate() -> Result<Self, Error> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|e| Error::OsRandomness(e.to_string()))?;
        Ok(Self::from_bytes(&seed))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            inner: ed25519_dalek::SigningKey::from_bytes(bytes),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.inner.sign(message)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey([redacted])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let inner =
            ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self { inner })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), Error> {
        use ed25519_dalek::Verifier;
        self.inner
            .verify(message, signature)
            .map_err(|_| Error::Verification)
    }

    pub fn multikey(&self) -> String {
        let mut encoded = Vec::with_capacity(ED25519_MULTIKEY_LENGTH);
        encoded.extend_from_slice(&ED25519_PUB_MULTIKEY_CODEC);
        encoded.extend_from_slice(&self.to_bytes());
        format!(
            "{MULTIKEY_MULTIBASE_PREFIX}{}",
            bs58::encode(encoded).into_string()
        )
    }

    pub fn from_multikey(multikey: &str) -> Result<Self, Error> {
        let body = multikey
            .strip_prefix(MULTIKEY_MULTIBASE_PREFIX)
            .ok_or(Error::InvalidMultikey)?;
        let decoded = bs58::decode(body)
            .into_vec()
            .map_err(|_| Error::InvalidMultikey)?;
        if decoded.len() != ED25519_MULTIKEY_LENGTH || decoded[..2] != ED25519_PUB_MULTIKEY_CODEC {
            return Err(Error::InvalidMultikey);
        }
        let bytes: [u8; 32] = decoded[2..]
            .try_into()
            .map_err(|_| Error::InvalidMultikey)?;
        Self::from_bytes(&bytes)
    }
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    const MESSAGE: &[u8] = b"trustmesh test vector";

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn signature_roundtrip() {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let signature = signing_key.sign(MESSAGE);
        signing_key
            .verifying_key()
            .verify(MESSAGE, &signature)
            .expect("signature must verify");
    }

    #[test]
    fn signatures_are_deterministic() {
        let first = SigningKey::from_bytes(&TEST_SEED).sign(MESSAGE);
        let second = SigningKey::from_bytes(&TEST_SEED).sign(MESSAGE);
        assert_eq!(first.to_bytes(), second.to_bytes());
    }

    #[test]
    fn tampered_message_rejected() {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let signature = signing_key.sign(MESSAGE);
        let verifying_key = signing_key.verifying_key();
        assert_eq!(
            verifying_key.verify(b"tampered", &signature),
            Err(Error::Verification)
        );
    }

    #[test]
    fn wrong_key_rejected() {
        let signer = SigningKey::from_bytes(&TEST_SEED);
        let other = SigningKey::from_bytes(&[7u8; 32]);
        let signature = signer.sign(MESSAGE);
        assert_eq!(
            other.verifying_key().verify(MESSAGE, &signature),
            Err(Error::Verification)
        );
    }

    #[test]
    fn generated_keys_are_unique_and_sign() {
        let a = SigningKey::generate().expect("OS entropy");
        let b = SigningKey::generate().expect("OS entropy");
        assert_ne!(a.to_bytes(), b.to_bytes());
        a.verifying_key()
            .verify(MESSAGE, &a.sign(MESSAGE))
            .expect("must verify");
    }

    #[test]
    fn multikey_roundtrip() {
        let verifying_key = SigningKey::from_bytes(&TEST_SEED).verifying_key();
        let multikey = verifying_key.multikey();
        assert!(multikey.starts_with('z'));
        assert_eq!(VerifyingKey::from_multikey(&multikey), Ok(verifying_key));
    }

    #[test]
    fn multikey_has_expected_shape() {
        let multikey = SigningKey::from_bytes(&TEST_SEED)
            .verifying_key()
            .multikey();
        let decoded = bs58::decode(&multikey[1..])
            .into_vec()
            .expect("valid base58btc");
        assert_eq!(decoded.len(), ED25519_MULTIKEY_LENGTH);
        assert_eq!(&decoded[..2], &ED25519_PUB_MULTIKEY_CODEC);
    }

    #[test]
    fn multikey_rejects_bad_input() {
        let valid = SigningKey::from_bytes(&TEST_SEED)
            .verifying_key()
            .multikey();
        let wrong_prefix = format!("z{}", bs58::encode([0xec, 0x01]).into_string());
        let not_multibase = &valid[1..];
        let invalid_base58_char = format!("z0OIl{}", &valid[1..6]);

        for bad in [
            wrong_prefix.as_str(),
            not_multibase,
            invalid_base58_char.as_str(),
        ] {
            assert_eq!(
                VerifyingKey::from_multikey(bad),
                Err(Error::InvalidMultikey),
                "{bad}"
            );
        }
    }

    #[test]
    fn debug_does_not_leak_secret_seed() {
        let signing_key = SigningKey::from_bytes(&TEST_SEED);
        let rendered = format!("{signing_key:?}");
        let seed_hex: String = TEST_SEED.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(rendered, "SigningKey([redacted])");
        assert!(!rendered.contains(&seed_hex[..16]));
    }
}
