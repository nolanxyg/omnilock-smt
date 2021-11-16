use ckb_hash::{Blake2b, Blake2bBuilder};
use lazy_static::lazy_static;
use sparse_merkle_tree::{default_store::DefaultStore, traits::Hasher, SparseMerkleTree, H256};

lazy_static! {
    pub static ref AUTH_SMT_VALUE: H256 = H256::from([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]);
}

pub const BLAKE2B_KEY: &[u8] = &[];
pub const BLAKE2B_LEN: usize = 32;
pub const PERSONALIZATION: &[u8] = b"ckb-default-hash";

pub struct CKBBlake2bHasher(Blake2b);

impl Default for CKBBlake2bHasher {
    fn default() -> Self {
        let blake2b = Blake2bBuilder::new(BLAKE2B_LEN)
            .personal(PERSONALIZATION)
            .key(BLAKE2B_KEY)
            .build();
        CKBBlake2bHasher(blake2b)
    }
}

impl Hasher for CKBBlake2bHasher {
    fn write_h256(&mut self, h: &H256) {
        self.0.update(h.as_slice());
    }
    fn finish(self) -> H256 {
        let mut hash = [0u8; 32];
        self.0.finalize(&mut hash);
        hash.into()
    }
    fn write_byte(&mut self, b: u8) {
        self.0.update(&[b][..]);
    }
}

pub type SMT = SparseMerkleTree<CKBBlake2bHasher, H256, DefaultStore<H256>>;

pub fn generate_root_proof(auth: &str) -> (H256, Vec<u8>) {
    let auth_bytes = hex::decode(&auth[2..]).unwrap();
    assert_eq!(auth_bytes.len(), 21);
    let mut auth_smt_key: [u8; 32] = Default::default();
    (&mut auth_smt_key[0..21]).copy_from_slice(auth_bytes.as_slice());
    let auth_pair: (H256, H256) = (auth_smt_key.into(), AUTH_SMT_VALUE.clone());

    let key_on_wl1: H256 = [
        111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let key_on_wl2: H256 = [
        222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let mut pairs = vec![
        (key_on_wl1, AUTH_SMT_VALUE.clone()),
        (key_on_wl2, AUTH_SMT_VALUE.clone()),
    ];
    pairs.extend(Vec::from([auth_pair]));

    let smt = new_smt(pairs);
    let root = smt.root();

    let proof = smt
        .merkle_proof(Vec::from([auth_pair.0]))
        .expect("gen proof");
    let compiled_proof = proof
        .clone()
        .compile(Vec::from([auth_pair]))
        .expect("compile proof");
    let test_on = compiled_proof
        .verify::<CKBBlake2bHasher>(root, Vec::from([auth_pair]))
        .expect("verify compiled proof");

    assert!(test_on);
    return (root.clone(), compiled_proof.into());
}

fn new_smt(pairs: Vec<(H256, H256)>) -> SMT {
    let mut smt = SMT::default();
    for (key, value) in pairs {
        smt.update(key, value).unwrap();
    }
    smt
}
