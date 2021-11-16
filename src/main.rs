use crate::smt::generate_root_proof;
use std::env;

mod smt;

fn main() {
    let args: Vec<String> = env::args().collect();
    assert_eq!(args.len(), 2);
    let auth = args.get(1).unwrap().as_str();
    if !auth.starts_with("0x") && !auth.starts_with("0X") {
        panic!("auth should be hex string, start with 0x")
    };

    let (root, proof) = generate_root_proof(auth);
    println!("root: 0x{}", hex::encode(root.as_slice()));
    println!("proof: 0x{}", hex::encode(proof.as_slice()));
}
