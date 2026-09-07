//! Validated runtime identity, independent of product wire and storage names.
use crate::{ContractId, Error};

/// A complete immutable delivery identity. Products retain their own wire DTOs
/// and may further constrain instance identifiers (for example canonical UUIDs).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIdentity {
    product_id: String,
    instance_id: String,
    contract_id: ContractId,
}

impl ClientIdentity {
    pub fn new(
        product_id: impl Into<String>,
        instance_id: impl Into<String>,
        contract_id: ContractId,
    ) -> Result<Self, Error> {
        let product_id = product_id.into();
        let instance_id = instance_id.into();
        let valid = |value: &str, max| {
            !value.is_empty()
                && value.len() <= max
                && value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        };
        if !valid(&product_id, 128) || !valid(&instance_id, 256) {
            return Err(Error::InvalidIdentity);
        }
        Ok(Self {
            product_id,
            instance_id,
            contract_id,
        })
    }

    pub fn product_id(&self) -> &str {
        &self.product_id
    }
    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }
    pub fn contract_id(&self) -> &ContractId {
        &self.contract_id
    }

    /// Compare all identity dimensions, never just an instance label. The error
    /// does not echo either identifier or modify credentials or durable records.
    pub fn ensure_matches(&self, other: &Self) -> Result<(), Error> {
        if self == other {
            Ok(())
        } else {
            Err(Error::IdentityMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identity(product: &str, instance: &str, contract: &str) -> ClientIdentity {
        ClientIdentity::new(product, instance, ContractId::new(contract).unwrap()).unwrap()
    }

    #[test]
    fn identity_is_bounded_and_never_normalizes_untrusted_identifiers() {
        assert!(
            ClientIdentity::new(
                "p".repeat(128),
                "i".repeat(256),
                ContractId::new("current").unwrap()
            )
            .is_ok()
        );
        for invalid in [
            "", " space", "space ", "a/b", "a\\b", "a\n", "a\0", "设备", "a:b",
        ] {
            for (product, instance) in [(invalid, "instance"), ("product", invalid)] {
                assert!(matches!(
                    ClientIdentity::new(product, instance, ContractId::new("current").unwrap()),
                    Err(Error::InvalidIdentity)
                ));
            }
        }
        assert!(
            ClientIdentity::new("p".repeat(129), "i", ContractId::new("current").unwrap()).is_err()
        );
        assert!(
            ClientIdentity::new("p", "i".repeat(257), ContractId::new("current").unwrap()).is_err()
        );
    }

    #[test]
    fn equality_checks_product_instance_and_contract_without_echoing_values() {
        let original = identity("product", "instance", "current");
        original.ensure_matches(&original.clone()).unwrap();
        for other in [
            identity("another-product", "instance", "current"),
            identity("product", "another-instance", "current"),
            identity("product", "instance", "another-contract"),
        ] {
            let error = original.ensure_matches(&other).unwrap_err();
            assert!(matches!(error, Error::IdentityMismatch));
            assert!(!error.to_string().contains("another"));
        }
        assert_eq!(original.product_id(), "product");
        assert_eq!(original.instance_id(), "instance");
        assert_eq!(original.contract_id().as_str(), "current");
    }
}
