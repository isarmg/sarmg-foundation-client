//! A single current envelope with explicit product domain and caller-provided object binding.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use xcsc_secret::{SecretBytes, SecretKey};
use zeroize::Zeroizing;

const MAGIC: &[u8; 4] = b"SGEV";
const NONCE_BYTES: usize = 12;
const MAX_PLAINTEXT_BYTES: usize = 1024 * 1024;
pub const MAX_BINDING_BYTES: usize = 4096;

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
    if binding.len() > MAX_BINDING_BYTES {
        return Err(Error::BindingTooLarge);
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
            <&Nonce<aes_gcm::aead::consts::U12>>::try_from(&nonce[..])
                .map_err(|_| Error::Crypto)?,
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
    if binding.len() > MAX_BINDING_BYTES {
        return Err(Error::BindingTooLarge);
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
            <&Nonce<aes_gcm::aead::consts::U12>>::try_from(&envelope[6..18])
                .map_err(|_| Error::Malformed)?,
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
    #[error("object binding exceeds the envelope budget")]
    BindingTooLarge,
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
    fn independent_hkdf_aes_gcm_vector_preserves_current_envelope_bytes() {
        // Independently generated with Python cryptography HKDF-SHA256 and
        // AESGCM (fixed test-only master/nonce), not this crate's seal function.
        let master = SecretKey::new([9; 32]);
        let expected_key = [
            0x1a, 0xd2, 0x78, 0x0b, 0x8e, 0xa1, 0xdf, 0xfd, 0xe4, 0xed, 0xad, 0x0c, 0x5c, 0x75,
            0x6e, 0x09, 0x48, 0x92, 0x34, 0x79, 0xc6, 0xd9, 0xbe, 0xab, 0x0b, 0xe5, 0x7d, 0xee,
            0xa8, 0x6f, 0x67, 0xeb,
        ];
        assert_eq!(
            &derive_key::<Test>(&master, b"object-1").unwrap()[..],
            &expected_key
        );
        let envelope = [
            0x53, 0x47, 0x45, 0x56, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x9b, 0x37, 0xbc, 0xe1, 0x9c, 0xdb, 0x9c, 0x13, 0xcc, 0x3e,
            0x16, 0xb2, 0x67, 0x3c, 0xea, 0x12, 0xaf, 0x36, 0x82, 0x04, 0xf8, 0x4d,
        ];
        assert_eq!(
            open::<Test>(&master, b"object-1", &envelope)
                .unwrap()
                .expose(),
            b"secret"
        );
        assert_eq!(
            open::<Test>(&master, b"object-2", &envelope).unwrap_err(),
            Error::Authentication
        );
        let cipher = Aes256Gcm::new_from_slice(&expected_key).unwrap();
        let aad = aad::<Test>(b"object-1").unwrap();
        let actual = cipher
            .encrypt(
                <&Nonce<aes_gcm::aead::consts::U12>>::try_from(&envelope[6..18]).unwrap(),
                Payload {
                    msg: b"secret",
                    aad: &aad,
                },
            )
            .unwrap();
        assert_eq!(&actual, &envelope[18..]);
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

    #[test]
    fn binding_has_a_hard_allocation_limit() {
        let key = SecretKey::new([9; 32]);
        let plain = SecretBytes::new(b"secret".to_vec());
        let oversized = vec![b'x'; MAX_BINDING_BYTES + 1];
        assert_eq!(
            seal::<Test>(&key, &oversized, &plain),
            Err(Error::BindingTooLarge)
        );
        assert!(matches!(
            open::<Test>(&key, &oversized, &[0; 34]),
            Err(Error::BindingTooLarge)
        ));
    }
}
