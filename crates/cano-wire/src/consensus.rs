use cano_types::Hash32;
use crate::error::WireError;
use crate::io::{WireEncode, WireDecode, put_u8, put_u16, put_u32, put_u64, put_bytes, get_u8, get_u16, get_u32, get_u64, get_bytes, len_to_u16, len_to_u32};

pub const MSG_TYPE_VOTE: u8           = 0x01;
pub const MSG_TYPE_QC: u8             = 0x02;
pub const MSG_TYPE_BLOCK_PROPOSAL: u8 = 0x03;

/// Vote message wire structure:
/// msg_type:        u8    // 0x01
/// version:         u8    // 0x01
/// chain_id:        u32
/// height:          u64
/// round:           u64
/// step:            u8    // 0 = Prevote, 1 = Precommit
/// block_id:        [u8;32]
/// validator_index: u16
/// reserved:        u16
/// signature:       Vec<u8> (length given by sig_len field)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub version:         u8,
    pub chain_id:        u32,
    pub height:          u64,
    pub round:           u64,
    pub step:            u8,
    pub block_id:        Hash32,
    pub validator_index: u16,
    pub reserved:        u16,
    pub signature:       Vec<u8>,
}

impl WireEncode for Vote {
    fn encode(&self, out: &mut Vec<u8>) {
        // msg_type + version
        put_u8(out, MSG_TYPE_VOTE);
        put_u8(out, self.version);
        // fixed fields
        put_u32(out, self.chain_id);
        put_u64(out, self.height);
        put_u64(out, self.round);
        put_u8(out, self.step);
        put_bytes(out, &self.block_id);
        put_u16(out, self.validator_index);
        put_u16(out, self.reserved);
        // sig length + sig bytes
        let sig_len = self.signature.len();
        let sig_len_u16 = len_to_u16(sig_len);
        put_u16(out, sig_len_u16);
        put_bytes(out, &self.signature);
    }
}

impl WireDecode for Vote {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let msg_type = get_u8(input)?;
        if msg_type != MSG_TYPE_VOTE {
            return Err(WireError::InvalidValue("unexpected msg_type for Vote"));
        }
        let version = get_u8(input)?;
        let chain_id = get_u32(input)?;
        let height = get_u64(input)?;
        let round = get_u64(input)?;
        let step = get_u8(input)?;
        let block_id_bytes = get_bytes(input, 32)?;
        let mut block_id = [0u8; 32];
        block_id.copy_from_slice(block_id_bytes);
        let validator_index = get_u16(input)?;
        let reserved = get_u16(input)?;
        let sig_len = get_u16(input)? as usize;
        let sig_bytes = get_bytes(input, sig_len)?.to_vec();
        Ok(Vote {
            version,
            chain_id,
            height,
            round,
            step,
            block_id,
            validator_index,
            reserved,
            signature: sig_bytes,
        })
    }
}

/// QuorumCertificate:
/// msg_type:      u8   // 0x02
/// version:       u8
/// chain_id:      u32
/// height:        u64
/// round:         u64
/// step:          u8
/// block_id:      [u8;32]
/// bitmap_len:    u16
/// signer_bitmap: [u8; bitmap_len]
/// sig_count:     u16
/// signatures:    sequence of (u16 len, bytes[len])
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumCertificate {
    pub version:       u8,
    pub chain_id:      u32,
    pub height:        u64,
    pub round:         u64,
    pub step:          u8,
    pub block_id:      Hash32,
    pub signer_bitmap: Vec<u8>,
    pub signatures:    Vec<Vec<u8>>,
}

impl WireEncode for QuorumCertificate {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, MSG_TYPE_QC);
        put_u8(out, self.version);
        put_u32(out, self.chain_id);
        put_u64(out, self.height);
        put_u64(out, self.round);
        put_u8(out, self.step);
        put_bytes(out, &self.block_id);
        // bitmap_len + signer_bitmap
        let bitmap_len = len_to_u16(self.signer_bitmap.len());
        put_u16(out, bitmap_len);
        put_bytes(out, &self.signer_bitmap);
        // sig_count + signatures
        let sig_count = len_to_u16(self.signatures.len());
        put_u16(out, sig_count);
        for sig in &self.signatures {
            let sig_len = len_to_u16(sig.len());
            put_u16(out, sig_len);
            put_bytes(out, sig);
        }
    }
}

impl WireDecode for QuorumCertificate {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let msg_type = get_u8(input)?;
        if msg_type != MSG_TYPE_QC {
            return Err(WireError::InvalidValue("unexpected msg_type for QuorumCertificate"));
        }
        let version = get_u8(input)?;
        let chain_id = get_u32(input)?;
        let height = get_u64(input)?;
        let round = get_u64(input)?;
        let step = get_u8(input)?;
        let block_id_bytes = get_bytes(input, 32)?;
        let mut block_id = [0u8; 32];
        block_id.copy_from_slice(block_id_bytes);
        let bitmap_len = get_u16(input)? as usize;
        let signer_bitmap = get_bytes(input, bitmap_len)?.to_vec();
        let sig_count = get_u16(input)? as usize;
        let mut signatures = Vec::with_capacity(sig_count);
        for _ in 0..sig_count {
            let sig_len = get_u16(input)? as usize;
            let sig = get_bytes(input, sig_len)?.to_vec();
            signatures.push(sig);
        }
        Ok(QuorumCertificate {
            version,
            chain_id,
            height,
            round,
            step,
            block_id,
            signer_bitmap,
            signatures,
        })
    }
}

/// BlockHeader (without embedded QC):
/// msg_type:       u8   // 0x03
/// version:        u8
/// chain_id:       u32
/// height:         u64
/// round:          u64
/// parent_block_id:Hash32
/// payload_hash:   Hash32
/// proposer_index: u16
/// reserved:       u16
/// tx_count:       u32
/// timestamp:      u64
/// qc_len:         u32   // length in bytes of QC encoding that follows
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version:        u8,
    pub chain_id:       u32,
    pub height:         u64,
    pub round:          u64,
    pub parent_block_id: Hash32,
    pub payload_hash:   Hash32,
    pub proposer_index: u16,
    pub reserved:       u16,
    pub tx_count:       u32,
    pub timestamp:      u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockProposal {
    pub header: BlockHeader,
    pub qc:     Option<QuorumCertificate>,
    /// raw transactions as encoded blobs; in later tasks we will parse them as cano-wire::tx::Transaction.
    pub txs:    Vec<Vec<u8>>,
}

impl WireEncode for BlockProposal {
    fn encode(&self, out: &mut Vec<u8>) {
        // First, encode QC into a temp buffer to get its length
        let qc_bytes = if let Some(ref qc) = self.qc {
            let mut qc_buf = Vec::new();
            qc.encode(&mut qc_buf);
            qc_buf
        } else {
            Vec::new()
        };
        let qc_len = len_to_u32(qc_bytes.len());

        // Now encode the header fields
        put_u8(out, MSG_TYPE_BLOCK_PROPOSAL);
        put_u8(out, self.header.version);
        put_u32(out, self.header.chain_id);
        put_u64(out, self.header.height);
        put_u64(out, self.header.round);
        put_bytes(out, &self.header.parent_block_id);
        put_bytes(out, &self.header.payload_hash);
        put_u16(out, self.header.proposer_index);
        put_u16(out, self.header.reserved);
        put_u32(out, self.header.tx_count);
        put_u64(out, self.header.timestamp);
        put_u32(out, qc_len);

        // Append QC bytes
        put_bytes(out, &qc_bytes);

        // Append each tx as u32 len + bytes
        for tx in &self.txs {
            let tx_len = len_to_u32(tx.len());
            put_u32(out, tx_len);
            put_bytes(out, tx);
        }
    }
}

impl WireDecode for BlockProposal {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let msg_type = get_u8(input)?;
        if msg_type != MSG_TYPE_BLOCK_PROPOSAL {
            return Err(WireError::InvalidValue("unexpected msg_type for BlockProposal"));
        }
        let version = get_u8(input)?;
        let chain_id = get_u32(input)?;
        let height = get_u64(input)?;
        let round = get_u64(input)?;
        let parent_block_id_bytes = get_bytes(input, 32)?;
        let mut parent_block_id = [0u8; 32];
        parent_block_id.copy_from_slice(parent_block_id_bytes);
        let payload_hash_bytes = get_bytes(input, 32)?;
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(payload_hash_bytes);
        let proposer_index = get_u16(input)?;
        let reserved = get_u16(input)?;
        let tx_count = get_u32(input)?;
        let timestamp = get_u64(input)?;
        let qc_len = get_u32(input)? as usize;

        let qc = if qc_len > 0 {
            let qc_bytes = get_bytes(input, qc_len)?;
            let mut qc_input = qc_bytes;
            Some(QuorumCertificate::decode(&mut qc_input)?)
        } else {
            None
        };

        let mut txs = Vec::with_capacity(tx_count as usize);
        for _ in 0..tx_count {
            let tx_len = get_u32(input)? as usize;
            let tx_bytes = get_bytes(input, tx_len)?.to_vec();
            txs.push(tx_bytes);
        }

        Ok(BlockProposal {
            header: BlockHeader {
                version,
                chain_id,
                height,
                round,
                parent_block_id,
                payload_hash,
                proposer_index,
                reserved,
                tx_count,
                timestamp,
            },
            qc,
            txs,
        })
    }
}