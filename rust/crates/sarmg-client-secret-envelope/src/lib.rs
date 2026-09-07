//! A single current envelope with explicit product domain and caller-provided object binding.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sarmg_client_secret::{SecretBytes, SecretKey};
use sha2::Sha256;
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"SGEV";
const NONCE_BYTES: usize = 12;
const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;

pub trait EnvelopeDomain {
    const DOMAIN: &'static [u8];
    const REVISION: u16;
}

pub fn seal<D: EnvelopeDomain>(
    master: &SecretKey<32>,
    binding: &[u8],
    plaintext: &SecretBytes,
) -> Result<Vec<u8>, Error> {
    if D::DOMAIN.is_empty() || binding.is_empty() {
        return Err(Error::MissingDomainBinding);
    }
    if plaintext.expose().len() > MAX_PLAINTEXT_BYTES {
        return Err(Error::PlaintextTooLarge);
    }
    let key = derive_key::<D>(master, binding)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| Error::Crypto)?;
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| Error::Randomness)?;
    let aad = aad::<D>(binding)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.expose(),
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;
    let mut output = Vec::with_capacity(6 + NONCE_BYTES + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&D::REVISION.to_be_bytes());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn open<D: EnvelopeDomain>(
    master: &SecretKey<32>,
    binding: &[u8],
    envelope: &[u8],
) -> Result<SecretBytes, Error> {
    if D::DOMAIN.is_empty() || binding.is_empty() {
        return Err(Error::MissingDomainBinding);
    }
    if envelope.len() < 6 + NONCE_BYTES + 16
        || envelope.len() > 6 + NONCE_BYTES + 16 + MAX_PLAINTEXT_BYTES
    {
        return Err(Error::Malformed);
    }
    if &envelope[..4] != MAGIC || u16::from_be_bytes([envelope[4], envelope[5]]) != D::REVISION {
        return Err(Error::WrongRevision);
    }
    let key = derive_key::<D>(master, binding)?;
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|_| Error::Crypto)?;
    let aad = aad::<D>(binding)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&envelope[6..18]),
            Payload {
                msg: &envelope[18..],
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok(SecretBytes::new(plaintext))
}

fn derive_key<D: EnvelopeDomain>(
    master: &SecretKey<32>,
    binding: &[u8],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let hk = Hkdf::<Sha256>::new(Some(D::DOMAIN), master.expose());
    let mut key = Zeroizing::new([0_u8; 32]);
    hk.expand(binding, key.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}
fn aad<D: EnvelopeDomain>(binding: &[u8]) -> Result<Vec<u8>, Error> {
    let domain_len = u16::try_from(D::DOMAIN.len()).map_err(|_| Error::MissingDomainBinding)?;
    let binding_len = u32::try_from(binding.len()).map_err(|_| Error::MissingDomainBinding)?;
    let mut aad = Vec::with_capacity(8 + D::DOMAIN.len() + binding.len());
    aad.extend_from_slice(&domain_len.to_be_bytes());
    aad.extend_from_slice(D::DOMAIN);
    aad.extend_from_slice(&D::REVISION.to_be_bytes());
    aad.extend_from_slice(&binding_len.to_be_bytes());
    aad.extend_from_slice(binding);
    Ok(aad)
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum Error {
    #[error("envelope requires a non-empty domain and binding")]
    MissingDomainBinding,
    #[error("plaintext exceeds the envelope budget")]
    PlaintextTooLarge,
    #[error("malformed envelope")]
    Malformed,
    #[error("envelope revision does not match the current domain revision")]
    WrongRevision,
    #[error("envelope authentication failed")]
    Authentication,
    #[error("cryptographic operation failed")]
    Crypto,
    #[error("secure randomness unavailable")]
    Randomness,
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Test;
    impl EnvelopeDomain for Test {
        const DOMAIN: &'static [u8] = b"test/credential";
        const REVISION: u16 = 1;
    }
    #[test]
    fn roundtrip_is_bound_to_object_and_tampering_fails() {
        let key = SecretKey::new([9; 32]);
        let plain = SecretBytes::new(b"secret".to_vec());
        let sealed = seal::<Test>(&key, b"object-1", &plain).unwrap();
        assert_eq!(
            open::<Test>(&key, b"object-1", &sealed).unwrap().expose(),
            b"secret"
        );
        assert_eq!(
            open::<Test>(&key, b"object-2", &sealed).unwrap_err(),
            Error::Authentication
        );
        let mut corrupt = sealed;
        *corrupt.last_mut().unwrap() ^= 1;
        assert_eq!(
            open::<Test>(&key, b"object-1", &corrupt).unwrap_err(),
            Error::Authentication
        );
    }
}
