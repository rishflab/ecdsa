# ECDSA signatures


#### Motivation
Bob wants prove that Alice has said something but Alice does not want anyone to be able to impersonate her.


## Review

### Group operations
```
X = x * G
```

where

`x` is a secret key. It is a a **scalar** (regular integer),

`G` is the generator (an agreed upon **point** on an elliptic surve)

`X` is the public key that corresponds to `x`

`*` is the group operation, the bouncing/mirroring thing from last week

`x * G` means we are applying the group operation to `G`, `x` number of times.

### Public and private keys

```
X = x * G
```

where `x` is the private key (scalar) and `X` is the public key (point)

### Inverse

```
s * s^-1 = 1
```

The inverse of a value multiplied by the inverse is 1


## Signing
The signature is a tuple `(r,s)`
```
(r, (k^-1 * H) + (k^-1 * r * x))
```

where `r` is a random point on the curve `r = k * G`

and `k` is a random scalar


## Verification

We want to recompute `s` using the public key `X`.

If the recomputed value matches, the `s` in the signature, the signature is valid



