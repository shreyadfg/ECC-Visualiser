# ECC Visualiser

An educational implementation of **Elliptic Curve Cryptography (ECC)** in Python built from first principles.

This project explores the mathematics behind elliptic curve cryptography by implementing the core algorithms used in modern public-key systems instead of relying on existing cryptographic libraries. It includes implementations of point arithmetic, ECC key generation, ElGamal encryption, ECDSA digital signatures, Elliptic Curve Diffie-Hellman (ECDH), and an interactive GUI for visualizing elliptic curves over finite fields.

The implementation uses a small toy curve so that every cryptographic operation can be inspected and understood mathematically.

> **Disclaimer:** This project is intended for educational purposes only and should **not** be used for production cryptography.

---

## Background

Elliptic Curve Cryptography operates over a finite field `Fp`, where all arithmetic is performed modulo a prime number `p`.

An elliptic curve is defined by the equation

```text
y² = x³ + ax + b  (mod p)
```

where the parameters satisfy

```text
4a³ + 27b² ≠ 0  (mod p)
```

to ensure the curve has no singularities.

A user's public key is generated through scalar multiplication

```text
Q = d × G
```

where

* `G` is the generator point
* `d` is the private key
* `Q` is the corresponding public key

The security of ECC relies on the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**—given only `G` and `Q`, determining the private key `d` is computationally infeasible for appropriately chosen curves.

---

## Features

### Core Elliptic Curve Arithmetic

* Point addition
* Point doubling
* Scalar multiplication using the Double-and-Add algorithm
* Modular inverse using the Extended Euclidean Algorithm
* Point order computation

### Cryptographic Algorithms

* ECC key pair generation
* ElGamal encryption
* ElGamal decryption
* ECDSA signature generation
* ECDSA signature verification
* Elliptic Curve Diffie-Hellman (ECDH)

### Interactive GUI

* Generate key pairs
* Encode plaintext onto the curve
* Encrypt and decrypt messages
* Generate and verify signatures
* Perform ECDH key exchange
* Visualize finite-field elliptic curves
* Visualize continuous real-valued elliptic curves

---

## Project Structure

```text
ECC-Visualiser/
├── ecc_toy.py          # Core ECC implementation
├── demo.py             # Command-line demonstration
├── playground_gui.py   # Interactive GUI
├── requirements.txt
└── README.md
```

---

## Toy Curve Parameters

The playground uses the following curve:

```text
Curve:
y² = x³ + x + 1  (mod 233)

Prime (p):      233
Generator (G):  (4, 5)
Order (n):      233
```

These intentionally small parameters make it possible to manually verify computations and visualize the underlying group operations.

---

## Implemented Algorithms

| Algorithm             | Status |
| --------------------- | :----: |
| Point Addition        |    ✅   |
| Point Doubling        |    ✅   |
| Scalar Multiplication |    ✅   |
| ECC Key Generation    |    ✅   |
| ElGamal Encryption    |    ✅   |
| ElGamal Decryption    |    ✅   |
| ECDSA                 |    ✅   |
| ECDH                  |    ✅   |

---

## Getting Started

### Clone the repository

```bash
git clone https://github.com/shreyadfg/ECC-Visualiser.git
cd ECC-Visualiser
```

### Install dependencies

```bash
pip install -r requirements.txt
```

If you don't have a `requirements.txt` yet:

```bash
pip install matplotlib numpy
```

### Run the command-line demonstration

```bash
python demo.py
```

### Launch the interactive GUI

```bash
python playground_gui.py
```

---

## Visualizations

The application provides two complementary visualizations of elliptic curves.

### Finite-Field View

Displays every valid point satisfying the curve equation over `Fp`. This is the discrete point set used during ECC computations and highlights generator points, encoded messages, and ciphertext points.

### Real-Valued View

Displays the continuous curve

```text
y² = x³ + ax + b
```

to provide geometric intuition before introducing finite-field arithmetic.

---

## Technologies

* Python
* Tkinter
* NumPy
* Matplotlib
* hashlib
* dataclasses

---

## Limitations

This implementation prioritizes readability and educational value over performance or security.

Current limitations include:

* Toy curve parameters
* Affine coordinate representation
* Simplified message-to-point encoding
* No side-channel protections
* No constant-time arithmetic
* Not compatible with standard curves such as `secp256r1`, `secp256k1`, or `Curve25519`

---

## Future Improvements

* Support for standard NIST and SEC curves
* Jacobian coordinates
* Montgomery ladder scalar multiplication
* RFC 6979 deterministic ECDSA
* Point compression
* ECIES implementation
* Unit testing
* Performance benchmarking
* Browser-based interactive visualizer

---

## References

* *Guide to Elliptic Curve Cryptography* — Hankerson, Menezes & Vanstone
* *An Introduction to Mathematical Cryptography* — Hoffstein, Pipher & Silverman
* SEC 1: Elliptic Curve Cryptography
* NIST FIPS 186-5 Digital Signature Standard

---

## License

This project is released under the MIT License.
