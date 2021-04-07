#![allow(non_snake_case)]

use secp256kfun::{g, marker::*, s, Point, Scalar, G};
use sha2::Digest;

pub struct Signature {
    /// x-coordinate of the R-value derived from the nonce k
    pub r: Scalar,
    /// "Signature proof"
    pub s: Scalar,
}

// Hints:
// We can generate a random scalar with Scalar::random(&mut rand::thread_rng())
// Use the g! macro for group operations eg. g!(x * y). The group operation is applied x times to y.
// Use the s! macro for scalar operations eg. s!(x + y * z)
// A scalar multiplied by its inverse is equal to one eg. a * a^-1 = 1
// Use .invert() to calculate the inverse of a scalar

pub fn sign(x: Scalar, msg: &str) -> Signature {
    // k is cryptograpphicaly secure random
    let k = Scalar::random(&mut rand::thread_rng());

    // perform the group operation k times on the curve generator
    // R = k * G
    let R = g!(k * G).mark::<Normal>();

    // Why are we throwing away the y value of this point? We are not. The curve equation is known by
    // both parties and the y value can be computed if x is known.
    // It seems that extracting the x-coordinate as opposed to the y-coordinate is a matter of convention.
    // Although perhaps recomputing x from y is harder.
    // R = k * G
    // r = the x component of R
    let r = {
        let (x, _) = R.coordinates();
        Scalar::from_bytes(x).unwrap().mark::<NonZero>().unwrap()
    };

    let mut hash = sha2::Sha256::default();
    hash.update(msg.as_bytes());
    let hash = Scalar::from_hash(hash);

    // k is cryptographically secure random
    // R = k * G
    // r = R.x (x component of R)
    // s = k^-1(hash + r * x) mod n
    let k_inv = k.invert();
    let s = s!(k_inv * (hash + r * x)).mark::<NonZero>().unwrap();

    Signature { r, s }
}

// To ensure that k is unique for each message, one may bypass random number generation
// completely and generate deterministic signatures by deriving k from both the message and the private key
pub fn verify(sig: Signature, msg: &str, X: Point) -> bool {
    let Signature { r, s } = sig;

    let mut hash = sha2::Sha256::default();
    hash.update(msg.as_bytes());
    let hash = Scalar::from_hash(hash);

    // s = k'
    // sk = k`.k.H + k`.r.x
    // k =  s'.k.'k.H + s'.k'.k.r.x
    // k = s'.H + s'.r.x
    // k = s'(H + r.x)
    //
    // _R = k * G
    // _R = s'(H + r.x) * G
    // _R = s'(H*G + r.x*G)
    // _R = s'(H*G + r.X)
    let s_inv = s.invert();
    let _R = g!(s_inv * (hash * G + r * X))
        .mark::<Normal>()
        .mark::<NonZero>()
        .unwrap();

    // _r = x_component(_R)
    let _r = {
        let (x, _) = _R.coordinates();
        Scalar::from_bytes(x).unwrap().mark::<NonZero>().unwrap()
    };

    // If `_r == r` the signature is valid
    r == _r
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
