//! Strict, product-neutral release and schema identities for Client tooling.
//! These data contracts do not supply administrator authentication or HTTP APIs.

pub use crate::schema_identity::{Error as SchemaIdentityError, SchemaIdentity};
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use thiserror::Error;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    #[serde(deserialize_with = "deserialize_identifier")]
    pub product: String,
    #[serde(deserialize_with = "deserialize_identifier")]
    pub version: String,
    #[serde(deserialize_with = "deserialize_source_revision")]
    pub source_revision: String,
    #[serde(deserialize_with = "deserialize_identifier")]
    pub target: String,
    #[serde(deserialize_with = "deserialize_sha256")]
    pub state_contract_sha256: String,
}

impl ReleaseIdentity {
    /// Parse and validate one current release-identity JSON document.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, ParseError> {
        let value: Self = serde_json::from_slice(bytes)?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_identifier("product", &self.product)?;
        validate_identifier("version", &self.version)?;
        validate_source_revision("source_revision", &self.source_revision)?;
        validate_identifier("target", &self.target)?;
        validate_sha256("state_contract_sha256", &self.state_contract_sha256)
    }
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("invalid contract JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Validation(#[from] ValidationError),
}

#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ValidationError {
    #[error("{field} must contain 1 to 128 ASCII letters, digits, '.', '_', ':' or '-'")]
    InvalidIdentifier { field: &'static str },
    #[error("{field} must be exactly 40 lowercase hexadecimal characters")]
    InvalidSourceRevision { field: &'static str },
    #[error("{field} must be exactly 64 lowercase hexadecimal characters")]
    InvalidSha256 { field: &'static str },
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(ValidationError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_source_revision(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.len() != 40 || !value.bytes().all(is_lower_hex) {
        return Err(ValidationError::InvalidSourceRevision { field });
    }
    Ok(())
}

fn validate_sha256(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.len() != 64 || !value.bytes().all(is_lower_hex) {
        return Err(ValidationError::InvalidSha256 { field });
    }
    Ok(())
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
}

fn deserialize_identifier<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_identifier("identifier", &value).map_err(D::Error::custom)?;
    Ok(value)
}

fn deserialize_source_revision<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_source_revision("source_revision", &value).map_err(D::Error::custom)?;
    Ok(value)
}

fn deserialize_sha256<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    validate_sha256("sha256", &value).map_err(D::Error::custom)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_identity_preserves_fields_and_rejects_noncanonical_input() {
        let value = ReleaseIdentity {
            product: "sample-product".into(),
            version: "1.0.0".into(),
            source_revision: "a".repeat(40),
            target: "x86_64-unknown-linux-gnu".into(),
            state_contract_sha256: "b".repeat(64),
        };
        let bytes = serde_json::to_vec(&value).unwrap();
        assert_eq!(ReleaseIdentity::from_slice(&bytes).unwrap(), value);
        let mut raw = serde_json::to_value(&value).unwrap();
        raw["source_revision"] = serde_json::Value::String("A".repeat(40));
        assert!(serde_json::from_value::<ReleaseIdentity>(raw.clone()).is_err());
        raw["source_revision"] = serde_json::Value::String("a".repeat(40));
        raw["git_sha"] = serde_json::Value::String("a".repeat(40));
        assert!(serde_json::from_value::<ReleaseIdentity>(raw).is_err());
    }
}
