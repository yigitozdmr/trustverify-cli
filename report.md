# TrustVerify – Brief Report

## 1. Why hashing alone is not enough to prove identity

Hashing is a one-way cryptographic function that converts input data into a fixed-length output (e.g., SHA-256). It is widely used to ensure **data integrity**, because even a small change in the input produces a completely different hash value.

In this project, hashing is used to detect whether files have been modified. If a file is changed, its hash will no longer match the stored value in `metadata.json`.

However, hashing alone is not sufficient to prove **identity (authenticity)**. This is because:

- Anyone can compute a hash of a file.
- An attacker can modify a file and simply generate a new valid hash.
- There is no mechanism in hashing to link the data to a specific sender.

For example, if an attacker modifies a file and recomputes its hash, the receiver cannot distinguish whether the file came from the original sender or the attacker.

Therefore:
- Hashing ensures **integrity**
- Hashing alone does **not ensure authenticity or identity**

---

## 2. How the private/public key relationship ensures non-repudiation

Public-key cryptography introduces a pair of keys:

- **Private Key** → kept secret by the sender  
- **Public Key** → shared with others  

In this project, the sender signs the SHA-256 hash of `metadata.json` using their **private key**. This produces a digital signature.

The receiver then verifies this signature using the sender’s **public key**.

This mechanism provides three important guarantees:

### a) Integrity
If the `metadata.json` file is modified after signing, the signature verification will fail.

### b) Authenticity
Only the owner of the private key could have created the signature.  
If verification succeeds, the receiver can trust that the data came from the legitimate sender.

### c) Non-repudiation
Because the signature is created using the sender’s private key, the sender cannot easily deny having signed the data.

This is known as **non-repudiation**:
> The sender cannot deny their involvement in the communication.

---

## Conclusion

This project combines:

- **SHA-256 hashing** → to detect file modifications (**integrity**)  
- **RSA digital signatures** → to verify the sender (**authenticity**) and ensure **non-repudiation**

Hashing alone is not enough for secure communication, but when combined with digital signatures, it provides a complete solution for both integrity and identity verification.