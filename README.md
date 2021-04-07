# ECDSA signatures

Sign and verify a message using a elliptic curve cryptography

## Review

### Group operations
```
X = x * G
```

where

`x` is a **secret key**. It is a a **scalar** value.

`G` is the generator (an agreed upon **point** on an elliptic surve)

`X` is the **public key** corresponding to the **secret key** `x`

`*` is the group operation, (the tangent intersection/mirroring thing)

`x * G` means we are applying the group operation to `G`, `x` number of times.

### Public and private keys

```
X = x * G
```

where `x` is the private key (scalar) and `X` is the public key (point)

### Inverse

```
a.a' = 1
```

A **scalar** `a` multiplied by its inverse `a'` is 1


## Signing
The signature is a tuple `(r,s)`

where

`s = k'.H + k'.r.x` 

`r` is the x component of `R`, a random point on the curve, where `R = k * G`

`k` is a random scalar

`H` is the hash of the message

`x` is the private key

The signature may seem arbitrary at first.
It is important to note that`s` is a function of the secret key and the message.
We use `X = x * G` to verify the signature.


## Verification

We want to recompute `s`. If the recomputed value matches, the `s` in the signature, the signature is valid

The problem is we don't know `x` or `k`. We need to eliminate these terms from the equation.

Given that:

```
X = x * G
```
```
R = k * G
```
```
k'.k = 1
```

We can calculate recompute the random point on the curve `_R`

```
s = k'
sk = k`.k.H + k`.r.x
k =  s'.k.'k.H + s'.k'.k.r.x
k = s'.H + s'.r.x
k = s'(H + r.x)


_R = k * G
_R = s'(H + r.x) * G
_R = s'(H*G + r.x*G)
_R = s'(H*G + r.X)

_r = x_component(_R)

_r == r
```

If `_r == r` the signature is valid

