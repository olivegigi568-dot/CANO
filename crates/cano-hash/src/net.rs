use cano_types::Hash32;
use cano_wire::net::{NetworkDelegationCert, CERT_TYPE_NETWORK_DELEGATION};
use cano_wire::io::{put_u8, put_u16, put_u64, put_bytes, len_to_u16};
use crate::hash::sha3_256_tagged;

/// Compute the canonical digest for a NetworkDelegationCert according to the spec.
/// This is what the root network key signs.
pub fn network_delegation_cert_digest(cert: &NetworkDelegationCert) -> Hash32 {
    let mut out = Vec::new();

    // cert_type and version
    put_u8(&mut out, CERT_TYPE_NETWORK_DELEGATION);
    put_u8(&mut out, cert.version);

    // validator_id, root_key_id
    put_bytes(&mut out, &cert.validator_id);
    put_bytes(&mut out, &cert.root_key_id);

    // leaf_kem_suite_id and reserved1
    put_u8(&mut out, cert.leaf_kem_suite_id);
    put_u8(&mut out, 0); // reserved1

    // leaf_pk_len + leaf_kem_pk
    let leaf_pk_len = cert.leaf_kem_pk.len();
    let leaf_pk_len_u16 = len_to_u16(leaf_pk_len);
    put_u16(&mut out, leaf_pk_len_u16);
    put_bytes(&mut out, &cert.leaf_kem_pk);

    // not_before, not_after
    put_u64(&mut out, cert.not_before);
    put_u64(&mut out, cert.not_after);

    // ext_len + ext_bytes
    let ext_len = cert.ext_bytes.len();
    let ext_len_u16 = len_to_u16(ext_len);
    put_u16(&mut out, ext_len_u16);
    put_bytes(&mut out, &cert.ext_bytes);

    sha3_256_tagged("CANO:NETCERT", &out)
}