# demo.py
from ecc_toy import (
    Curve, generate_keypair, encode_message_to_point, decode_point_to_message,
    elgamal_encrypt, elgamal_decrypt, ecdsa_sign, ecdsa_verify, ecdh_shared_secret
)

# Toy curve parameters (small prime for demonstration)
p = 233
a = 1
b = 1
Gx, Gy = 4, 5
n = 233
curve = Curve(p, a, b, Gx, Gy, n=n, name="toy-233")

print("Curve:", curve.name, "p=", curve.p, "a=", curve.a, "b=", curve.b)
print("Base point G:", curve.G)

# Key generation (Alice)
d_alice, Q_alice = generate_keypair(curve)
print("\nAlice private key d =", d_alice)
print("Alice public key Q =", Q_alice)

# Message -> point
msg = b"hello ECC demo"
M = encode_message_to_point(curve, msg)
print("\nEncoded message point M:", M)
print("Decoded (toy) from M:", decode_point_to_message(curve, M))

# ElGamal encryption
C1, C2 = elgamal_encrypt(curve, Q_alice, M)
print("\nElGamal ciphertext:")
print("C1 =", C1)
print("C2 =", C2)

# Decrypt
M_rec = elgamal_decrypt(curve, d_alice, C1, C2)
print("\nElGamal decrypted point M_rec:", M_rec)
print("Decode:", decode_point_to_message(curve, M_rec))

# ECDSA sign & verify
r, s = ecdsa_sign(curve, d_alice, msg)
print("\nECDSA signature (r,s):", (r,s))
ok = ecdsa_verify(curve, Q_alice, msg, (r,s))
print("ECDSA verification result:", ok)

# Tampered message check
bad = b"tampered msg"
print("\nVerify signature on tampered message:", ecdsa_verify(curve, Q_alice, bad, (r,s)))

# ----------------- ECDH Demo -----------------
d_alice2, Q_alice2 = generate_keypair(curve)
d_bob, Q_bob = generate_keypair(curve)

S1 = ecdh_shared_secret(curve, d_alice2, Q_bob)
S2 = ecdh_shared_secret(curve, d_bob, Q_alice2)

print("\nECDH shared secret (Alice computes):", S1)
print("ECDH shared secret (Bob computes):  ", S2)
print("Shared secrets match? ->", S1 == S2)
