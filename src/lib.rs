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
// A scalar multiplied by its inverse is equal to 1. x * x^-1 = 1
// Use .invert() to calculate the inverse of a scalar

pub fn sign(x: Scalar, msg: &str) -> Signature {
    // k is cryptographically secure random
    // R = k * G
    // r = R.x (x component of R)
    let r = todo!();
    // s = k^-1(hash + r * x) mod n
    let s = todo!();

    Signature { r, s }
}

// To ensure that k is unique for each message, one may bypass random number generation
// completely and generate deterministic signatures by deriving k from both the message and the private key
pub fn verify(sig: Signature, msg: &str, X: Point) -> bool {
    let Signature { r, s } = sig;

    // R' is the candidate curve point, R_candidate

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

    r_candidate = todo!();

    // if R'.x == r, the signature is valid,
    r_candidate == r
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
