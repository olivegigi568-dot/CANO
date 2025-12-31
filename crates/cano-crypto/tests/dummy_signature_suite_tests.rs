use std::sync::Arc;
use cano_crypto::{CryptoError, SignatureSuite, Signer, CryptoProvider, StaticCryptoProvider};
use cano_types::Hash32;

struct DummySignatureSuite;

impl SignatureSuite for DummySignatureSuite {
    fn suite_id(&self) -> u8 { 0xFF } // a test-only suite_id

    fn public_key_len(&self) -> usize { 32 }

    fn signature_len(&self) -> usize { 32 }

    fn verify(&self, pk: &[u8], msg_digest: &Hash32, sig: &[u8]) -> Result<(), CryptoError> {
        // Simple rule: sig must equal msg_digest, pk is ignored except length.
        if pk.len() != 32 {
            return Err(CryptoError::InvalidKey);
        }
        if sig.len() != 32 {
            return Err(CryptoError::InvalidSignature);
        }
        if &sig[..] == msg_digest {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        }
    }
}

struct DummySigner {
    pk: [u8; 32],
}

impl Signer for DummySigner {
    fn suite_id(&self) -> u8 { 0xFF }

    fn public_key(&self) -> &[u8] {
        &self.pk
    }

    fn sign(&self, msg_digest: &Hash32) -> Result<Vec<u8>, CryptoError> {
        Ok(msg_digest.to_vec())
    }
}

#[test]
fn dummy_signature_roundtrip() {
    let suite = DummySignatureSuite;
    let signer = DummySigner { pk: [1u8; 32] };

    let digest: Hash32 = [7u8; 32];

    let sig = signer.sign(&digest).expect("sign");
    assert_eq!(sig.len(), 32);

    suite.verify(signer.public_key(), &digest, &sig).expect("verify ok");

    let mut wrong = sig.clone();
    wrong[0] ^= 0x01;
    let err = suite.verify(signer.public_key(), &digest, &wrong).unwrap_err();
    assert!(matches!(err, CryptoError::InvalidSignature));
}

#[test]
fn static_provider_resolves_suite() {
    let suite = Arc::new(DummySignatureSuite);
    let provider = StaticCryptoProvider::new().with_signature_suite(suite.clone());

    let resolved = provider.signature_suite(0xFF).expect("suite exists");
    assert_eq!(resolved.suite_id(), 0xFF);

    assert!(provider.signature_suite(0x01).is_none());
}