use secp256kfun::hash::{HashAdd, Tagged};
use secp256kfun::{g, marker::*, Point, Scalar, G};
use sha2::digest::Digest;

pub struct Hash;
struct R;
struct S;

// y^2 = x^3 + 7

fn sign(x: Scalar, msg: String) -> (Scalar, Scalar) {
    // k is cryptograpphicaly secure random
    let k = Scalar::random(&mut rand::thread_rng());
    // perform the group operation k times on the curve generator
    // either x1 or y1
    let x1y1 = g!(k * G);
    let (r, _) = x1y1.coordinates();
    let r = Scalar::from_bytes(r).unwrap();
    let hash = sha2::Sha256::default().add(&msg).finalize();
    let hash = Scalar::from_hash(hash);
    // s = k^-1(hash + r * x) mod n
    let s = k.invert() * (hash + &r * x);
    (r, s)
}

// To ensure that
// k is unique for each message, one may bypass random number generation completely and generate deterministic signatures by deriving
// k from both the message and the private key
fn verify(r: R, s: R, pub_key: PubKey) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sign_and_verify() {}
}
