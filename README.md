# ECC Playground

An educational implementation of **Elliptic Curve Cryptography (ECC)** in Python built from first principles.

This project explores the mathematics behind elliptic curve cryptography by implementing the core algorithms used in modern public-key systems instead of relying on existing cryptographic libraries. It includes implementations of point arithmetic, ECC key generation, ElGamal encryption, ECDSA digital signatures, Elliptic Curve Diffie-Hellman (ECDH), and an interactive GUI for visualizing elliptic curves over finite fields.

The implementation uses a small toy curve to make the underlying mathematics easy to inspect and understand.

> **Disclaimer:** This project is intended for educational purposes only and should **not** be used for real-world cryptographic applications.

---

## Background

Elliptic Curve Cryptography is based on the algebraic structure of curves defined over finite fields.

For a prime field ( \mathbb{F}_p ), an elliptic curve is given by

[
y^2 \equiv x^3 + ax + b \pmod p
]

where

[
4a^3 + 27b^2 \not\equiv 0 \pmod p
]

to ensure that the curve is non-singular.

ECC security relies on the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**.

Given

[
Q = dG
]

where

* (G) is the generator point,
* (d) is the private key,
* (Q) is the public key,

recovering (d) from (Q) is computationally infeasible for sufficiently large curves.

---

## Features

### Core Elliptic Curve Arithmetic

* Point addition
* Point doubling
* Scalar multiplication (Double-and-Add)
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
ECC-Playground/
├── ecc_toy.py          # Core ECC implementation
├── demo.py             # Command-line demonstration
├── playground_gui.py   # Interactive GUI
├── requirements.txt
└── README.md
```

---

## Example Curve

The playground uses the toy curve

[
E : y^2 \equiv x^3 + x + 1 \pmod{233}
]

with generator point

[
G = (4,5)
]

The parameters are intentionally small so that every operation can be visualized and verified manually.

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

The application provides two complementary views of elliptic curves.

### Finite-Field Plot

Displays the discrete set of points satisfying the curve equation over the finite field ( \mathbb{F}_p ). This represents the actual points used during ECC computations.

### Real-Valued Plot

Displays the continuous curve

[
y^2 = x^3 + ax + b
]

to provide geometric intuition before transitioning to finite-field arithmetic.

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

This implementation prioritizes readability and educational value over performance.

Current limitations include:

* Toy curve parameters
* Affine coordinates only
* Simplified message-to-point encoding
* No constant-time operations
* No side-channel resistance
* Not compatible with standard curves such as secp256r1 or Curve25519

---

## Future Improvements

* Jacobian coordinates
* Montgomery ladder scalar multiplication
* Standard NIST and SEC curves
* RFC 6979 deterministic ECDSA
* Point compression
* ECIES implementation
* Unit tests
* Performance benchmarking
* Web-based interactive playground

---

## References

* *Guide to Elliptic Curve Cryptography* — Hankerson, Menezes & Vanstone
* *An Introduction to Mathematical Cryptography* — Hoffstein, Pipher & Silverman
* SEC 1: Elliptic Curve Cryptography Standards
* NIST FIPS 186-5 Digital Signature Standard

---

## License

This repository is released under the MIT License.

---

If you find a bug, have suggestions, or would like to contribute, feel free to open an issue or submit a pull request.
