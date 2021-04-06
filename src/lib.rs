#![allow(non_snake_case)]

use secp256kfun::{g, marker::*, s, Point, Scalar, G};
use sha2::Digest;

// secp256k1 equation: y^2 = x^3 + 7

pub struct Signature {
    /// x-coordinate of the R-value derived from the nonce k
    pub r: Scalar,
    /// "Signature proof"
    pub s: Scalar,
}

pub fn sign(x: Scalar, msg: &str) -> Signature {
    // k is cryptograpphicaly secure random
    let k = Scalar::random(&mut rand::thread_rng());

    // perform the group operation k times on the curve generator
    // R = k * G
    let R = g!(k * G).mark::<Normal>();

    // It seems that extracting the x-coordinate as opposed to the y-coordinate is a matter of convention.
    // Although perhaps recomputing x from y is harder.
    let r = {
        let (x, _) = R.coordinates();
        Scalar::from_bytes(x).unwrap().mark::<NonZero>().unwrap()
    };

    let mut hash = sha2::Sha256::default();
    hash.update(msg.as_bytes());
    let hash = Scalar::from_hash(hash);

    // s = k^-1(hash + r * x) mod n
    let k_inv = k.invert();
    let s = s!(k_inv * (hash + r * x)).mark::<NonZero>().unwrap();

    Signature { r, s }
}

// To ensure that
// k is unique for each message, one may bypass random number generation completely and generate deterministic signatures by deriving
// k from both the message and the private key

pub fn verify(sig: Signature, msg: &str, X: Point) -> bool {
    let Signature { r, s } = sig;

    let mut hash = sha2::Sha256::default();
    hash.update(msg.as_bytes());
    let hash = Scalar::from_hash(hash);

    // R' = s^-1(hash * G + r * X)
    // R' = (s^-1 * hash * G + s^-1 * r * X)
    // R' = (s^-1 * hash * G + s^-1 * r * x * G)
    // R' = (s^-1 *hash + s^-1 * r * x) * G
    // R' = s^-1(hash + r * x) * G
    // R' = (k^-1(hash + r * x))^-1 * (hash + r * x) * G
    // R' = (k^-1)^-1 * (hash + r * x)^-1 * (hash + r * x) * G
    // R' = k * 1 * G
    // R' = k * G

    // k = s^-1(hash + r * x)
    // k * s = s * s^-1(hash + r * x)
    // k * k^-1(hash + r * x) = hash + r * x
    // hash + r * x = hash + r * x
    let s_inv = s.invert();
    let R_candidate = g!(s_inv * (hash * G + r * X))
        .mark::<Normal>()
        .mark::<NonZero>()
        .unwrap();

    let r_candidate = {
        let (x, _) = R_candidate.coordinates();
        Scalar::from_bytes(x).unwrap().mark::<NonZero>().unwrap()
    };

    r == r_candidate
}

#[cfg(test)]
mod tests {
    use rand::thread_rng;

    use super::*;
    #[test]
    fn sign_and_verify() {
        let x = Scalar::random(&mut thread_rng());
        let X = g!(x * G).mark::<Normal>();

        let msg = String::from("hello world");

        let sig = sign(x, &msg);

        assert!(verify(sig, &msg, X))
    }
}
