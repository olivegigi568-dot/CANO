use crate::{SignatureSuite, KemSuite, AeadSuite};
use std::collections::HashMap;
use std::sync::Arc;

/// Abstract provider used by consensus, net, and execution code.
/// It resolves suite IDs to verification/encapsulation primitives.
pub trait CryptoProvider: Send + Sync {
    /// Lookup a signature suite implementation by suite_id.
    fn signature_suite(&self, suite_id: u8) -> Option<&dyn SignatureSuite>;

    /// Lookup a KEM suite implementation by suite_id.
    fn kem_suite(&self, suite_id: u8) -> Option<&dyn KemSuite>;

    /// Lookup an AEAD suite implementation by suite_id.
    fn aead_suite(&self, suite_id: u8) -> Option<&dyn AeadSuite>;
}

pub struct StaticCryptoProvider {
    sig_suites: HashMap<u8, Arc<dyn SignatureSuite>>,
    kem_suites: HashMap<u8, Arc<dyn KemSuite>>,
    aead_suites: HashMap<u8, Arc<dyn AeadSuite>>,
}

impl StaticCryptoProvider {
    pub fn new() -> Self {
        Self {
            sig_suites: HashMap::new(),
            kem_suites: HashMap::new(),
            aead_suites: HashMap::new(),
        }
    }

    pub fn with_signature_suite(mut self, suite: Arc<dyn SignatureSuite>) -> Self {
        self.sig_suites.insert(suite.suite_id(), suite);
        self
    }

    pub fn with_kem_suite(mut self, suite: Arc<dyn KemSuite>) -> Self {
        self.kem_suites.insert(suite.suite_id(), suite);
        self
    }

    pub fn with_aead_suite(mut self, suite: Arc<dyn AeadSuite>) -> Self {
        self.aead_suites.insert(suite.suite_id(), suite);
        self
    }
}

impl CryptoProvider for StaticCryptoProvider {
    fn signature_suite(&self, suite_id: u8) -> Option<&dyn SignatureSuite> {
        self.sig_suites.get(&suite_id).map(|a| a.as_ref())
    }

    fn kem_suite(&self, suite_id: u8) -> Option<&dyn KemSuite> {
        self.kem_suites.get(&suite_id).map(|a| a.as_ref())
    }

    fn aead_suite(&self, suite_id: u8) -> Option<&dyn AeadSuite> {
        self.aead_suites.get(&suite_id).map(|a| a.as_ref())
    }
}