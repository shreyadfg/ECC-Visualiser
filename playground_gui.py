# playground_gui.py


import tkinter as tk
from tkinter import scrolledtext
from ecc_toy import (
    Curve, generate_keypair, encode_message_to_point, decode_point_to_message,
    elgamal_encrypt, elgamal_decrypt, ecdsa_sign, ecdsa_verify, ecdh_shared_secret,
    scalar_mult
)

import matplotlib.pyplot as plt
import numpy as np

# Toy curve parameters
p = 233; a = 1; b = 1; Gx, Gy = 4, 5; n = 233
curve = Curve(p, a, b, Gx, Gy, n=n, name='toy-233')

root = tk.Tk()
root.title("ECC Playground (Real + Finite-Field Plots)")

def append(text: str):
    log.configure(state='normal')
    log.insert(tk.END, text + "\n")
    log.configure(state='disabled')
    log.see(tk.END)

def gen_keys():
    global priv, pub
    priv, pub = generate_keypair(curve)
    append(f"Generated keys -> priv: {priv}, pub: {pub}")

def encode_msg():
    msg = entry_msg.get().encode()
    global M_point
    try:
        M_point = encode_message_to_point(curve, msg)
        append(f"Encoded message to point: {M_point}")
    except Exception as e:
        append("Encoding failed: " + str(e))

def encrypt():
    if 'pub' not in globals():
        append("Generate keys first."); return
    if 'M_point' not in globals():
        append("Encode message first."); return
    global C1, C2
    C1, C2 = elgamal_encrypt(curve, pub, M_point)
    append(f"Encrypted -> C1: {C1}, C2: {C2}")

def decrypt():
    if 'C1' not in globals() or 'C2' not in globals():
        append("No ciphertext found."); return
    M = elgamal_decrypt(curve, priv, C1, C2)
    append(f"Decrypted M: {M} -> {decode_point_to_message(curve, M)}")

def sign_msg():
    if 'priv' not in globals():
        append("Generate keys first."); return
    msg = entry_msg.get().encode()
    sig = ecdsa_sign(curve, priv, msg)
    global signature
    signature = sig
    append(f"Signature: {sig}")

def verify_sig():
    if 'signature' not in globals():
        append("Sign a message first."); return
    msg = entry_msg.get().encode()
    result = ecdsa_verify(curve, pub, msg, signature)
    append(f"Signature verification on current message: {result}")

def ecdh_gui():
    # ECDH demo between two parties
    dA, QA = generate_keypair(curve)
    dB, QB = generate_keypair(curve)
    S_A = ecdh_shared_secret(curve, dA, QB)
    S_B = ecdh_shared_secret(curve, dB, QA)
    append("== ECDH Demo ==")
    append(f"Alice priv: {dA}, pub: {QA}")
    append(f"Bob   priv: {dB}, pub: {QB}")
    append(f"Alice computes shared secret (x): {S_A}")
    append(f"Bob   computes shared secret (x): {S_B}")
    append(f"Shared secrets match? {S_A == S_B}")

# -------------------- Plot finite-field points -------------------------
def plot_finite_field():
    xs = []
    ys = []
    for x in range(p):
        rhs = (x*x*x + a*x + b) % p
        for y in range(p):
            if (y*y) % p == rhs:
                xs.append(x)
                ys.append(y)

    plt.figure(figsize=(7,7))
    plt.scatter(xs, ys, s=12, color='black', label='Points (mod p)')

    # highlight G
    plt.scatter(curve.G.x, curve.G.y, color='green', s=100, label='Generator G')

    # highlight M, C1, C2 if exist
    if 'M_point' in globals():
        plt.scatter(M_point.x, M_point.y, color='blue', s=100, label='Message M')
    if 'C1' in globals():
        plt.scatter(C1.x, C1.y, color='red', s=100, marker='x', label='C1')
    if 'C2' in globals():
        plt.scatter(C2.x, C2.y, color='orange', s=100, marker='x', label='C2')

    plt.title(f'Elliptic Curve over Finite Field (p={p})')
    plt.xlabel('x'); plt.ylabel('y'); plt.grid(True); plt.legend()
    plt.show()

# -------------------- Plot real-valued smooth curve --------------------
def plot_real_curve():
    X = np.linspace(-6, 6, 2000)
    Y2 = X**3 + a*X + b
    plt.figure(figsize=(8,6))
    mask = Y2 >= 0
    Xv = X[mask]
    Yv = np.sqrt(Y2[mask])
    plt.plot(Xv, Yv, color='blue', label='y = +sqrt(x^3 + ax + b)')
    plt.plot(Xv, -Yv, color='red', label='y = -sqrt(x^3 + ax + b)')

    # Optionally plot a projected G/M/C points by using their x values (real-projection)
    if 'M_point' in globals():
        # project point.x to real curve (choose sign matching y)
        plt.scatter([M_point.x], [float(M_point.y)], color='blue', s=80, label='M (projected)')
    plt.title('Real-valued Elliptic Curve (smooth)')
    plt.xlabel('x'); plt.ylabel('y'); plt.grid(True); plt.legend()
    plt.show()

# -------------------- GUI layout --------------------------------------
frame = tk.Frame(root); frame.pack(padx=10, pady=10)

tk.Label(frame, text="Message:").grid(row=0, column=0, sticky='w')
entry_msg = tk.Entry(frame, width=40); entry_msg.grid(row=0, column=1, columnspan=5)

tk.Button(frame, text="Generate keys", command=gen_keys).grid(row=1, column=0, pady=6)
tk.Button(frame, text="Encode msg", command=encode_msg).grid(row=1, column=1)
tk.Button(frame, text="Encrypt", command=encrypt).grid(row=1, column=2)
tk.Button(frame, text="Decrypt", command=decrypt).grid(row=1, column=3)

tk.Button(frame, text="Sign", command=sign_msg).grid(row=2, column=0, pady=6)
tk.Button(frame, text="Verify", command=verify_sig).grid(row=2, column=1)
tk.Button(frame, text="Diffie-Hellman", command=ecdh_gui).grid(row=2, column=2, padx=4)

tk.Button(frame, text="Plot Finite-Field Curve", command=plot_finite_field, bg='lightyellow').grid(row=3, column=0, pady=8)
tk.Button(frame, text="Plot Real Smooth Curve", command=plot_real_curve, bg='lightgreen').grid(row=3, column=1, pady=8)

log = scrolledtext.ScrolledText(root, width=90, height=18, state='disabled'); log.pack(padx=10, pady=10)
append("ECC Playground ready — use the buttons to run flows and generate plots.")
root.mainloop()
