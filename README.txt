ECC Playground (toy) - educational project

Files:
- ecc_toy.py        : ECC implementation (point ops, ElGamal, ECDSA, ECDH)
- demo.py           : Command-line demo for keygen, encrypt/decrypt, sign/verify, ECDH
- playground_gui.py : Tkinter GUI with both plots (finite-field + real-valued)
- README.txt        : this file

How to run:
1) Command line demo:
   $ python3 demo.py

2) GUI (requires graphical environment):
   $ python3 playground_gui.py

Notes:
- Toy curve parameters: p=233, a=1, b=1, G=(4,5), n=233. This is small for demonstration.
- Finite-field plot correctly shows discrete points (real ECC). Real-valued plot is for intuition.
- This project is educational only. Do NOT use this for security-sensitive tasks.
