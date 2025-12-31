use cano_hash::network_delegation_cert_digest;
use cano_wire::net::NetworkDelegationCert;

fn make_test_cert() -> NetworkDelegationCert {
    NetworkDelegationCert {
        version: 1,
        validator_id: [0x11; 32],
        root_key_id: [0x22; 32],
        leaf_kem_suite_id: 1,
        leaf_kem_pk: vec![0x33, 0x44, 0x55, 0x66],
        not_before: 1700000000,
        not_after: 1800000000,
        ext_bytes: vec![0x77, 0x88],
        sig_suite_id: 1,
        sig_bytes: vec![0x99, 0xAA, 0xBB], // Not part of digest
    }
}

#[test]
fn network_delegation_cert_digest_is_stable() {
    let cert = make_test_cert();
    let digest1 = network_delegation_cert_digest(&cert);
    let digest2 = network_delegation_cert_digest(&cert);
    assert_eq!(digest1, digest2);
}

#[test]
fn network_delegation_cert_digest_changes_with_leaf_kem_pk() {
    let cert1 = make_test_cert();
    let mut cert2 = make_test_cert();
    cert2.leaf_kem_pk = vec![0xDD, 0xEE, 0xFF];

    let digest1 = network_delegation_cert_digest(&cert1);
    let digest2 = network_delegation_cert_digest(&cert2);
    assert_ne!(digest1, digest2);
}

#[test]
fn network_delegation_cert_digest_ignores_sig_bytes() {
    let cert1 = make_test_cert();
    let mut cert2 = make_test_cert();
    cert2.sig_bytes = vec![0xCC, 0xDD, 0xEE, 0xFF, 0x00];

    // Digest should be the same since sig_bytes is NOT part of the cert digest
    let digest1 = network_delegation_cert_digest(&cert1);
    let digest2 = network_delegation_cert_digest(&cert2);
    assert_eq!(digest1, digest2);
}

#[test]
fn network_delegation_cert_digest_ignores_sig_suite_id() {
    let cert1 = make_test_cert();
    let mut cert2 = make_test_cert();
    cert2.sig_suite_id = 2;

    // Digest should be the same since sig_suite_id is NOT part of the cert digest
    let digest1 = network_delegation_cert_digest(&cert1);
    let digest2 = network_delegation_cert_digest(&cert2);
    assert_eq!(digest1, digest2);
}