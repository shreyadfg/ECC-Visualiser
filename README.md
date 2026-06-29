# ECC Playground

ECC Playground is a Python implementation of the fundamental building blocks of Elliptic Curve Cryptography (ECC). The goal of this project is to understand how modern public-key cryptography works by implementing the underlying mathematics instead of relying on existing cryptographic libraries.

The project includes implementations of point arithmetic, ECC key generation, ElGamal encryption, ECDSA signatures, ECDH key exchange, and an interactive GUI for experimenting with these operations and visualizing elliptic curves.

> **Note:** This project uses a small toy curve for educational purposes only and should not be used in production environments.

---

## Features

- Elliptic Curve point addition and doubling
- Scalar multiplication (Double-and-Add)
- ECC public/private key generation
- ElGamal encryption and decryption
- ECDSA signature generation and verification
- Elliptic Curve Diffie-Hellman (ECDH)
- Finite-field elliptic curve visualization
- Real-valued elliptic curve visualization
- Interactive Tkinter playground

---

## Project Structure

```
ECC-Playground/
├── ecc_toy.py          # Core ECC implementation
├── demo.py             # CLI demonstration
├── playground_gui.py   # Interactive GUI
└── README.md
```

---

## Running the project

Clone the repository

```bash
git clone https://github.com/shreyadfg/ECC-Visualiser.git
cd ECC-Visualiser
```

Install dependencies

```bash
pip install matplotlib numpy
```

Run the command-line demo

```bash
python demo.py
```

Launch the GUI

```bash
python playground_gui.py
```

---

## Algorithms Implemented

| Algorithm | Status |
|-----------|--------|
| Point Addition | ✅ |
| Point Doubling | ✅ |
| Scalar Multiplication | ✅ |
| Key Generation | ✅ |
| ECC ElGamal | ✅ |
| ECDSA | ✅ |
| ECDH | ✅ |

---

## Visualizations

The GUI includes two different views of elliptic curves.

- **Finite-field plot** showing the actual points used during ECC computations.
- **Real-valued plot** to provide intuition behind the curve geometry.

The application can also highlight generated keys, encoded messages, and ciphertext points.

---

## Technologies

- Python
- Tkinter
- NumPy
- Matplotlib
- hashlib

---

## Limitations

This implementation prioritizes readability over performance and security.

Some simplifications include:

- Small toy curve parameters
- Simple message-to-point encoding
- No side-channel protections
- Not compatible with standardized curves such as secp256r1 or Curve25519

---

## Future Work

- Standard curve support
- Jacobian coordinates
- Deterministic ECDSA (RFC 6979)
- ECIES implementation
- Point compression
- Performance benchmarking
- Unit tests

---

## License

This project is intended for educational purposes.
