# TrustVerify CLI

TrustVerify is a Python-based command-line tool designed to ensure **file integrity** and **authenticity** using:

- 🔐 SHA-256 hashing (for integrity)
- 🔑 RSA digital signatures (for authenticity and non-repudiation)

---

## 🚀 Features

- Generate SHA-256 hash for any file
- Create a `metadata.json` manifest for a directory
- Detect file modifications (tampering)
- Generate RSA public/private key pairs
- Sign the manifest using a private key
- Verify signature using a public key
- Full verification: integrity + authenticity

---

## 📦 Installation

```bash
pip install -r requirements.txt

Usage
1. Generate hash for a file
python trustverify.py hash test_data/sample.txt

2. Create a manifest (metadata.json)
python trustverify.py manifest test_data -o metadata.json

3. Check file integrity
python trustverify.py check test_data -m metadata.json

4. Generate RSA keys
python trustverify.py genkeys

5. Sign the manifest
python trustverify.py sign -m metadata.json -k private_key.pem -s metadata.sig

6. Verify signature only
python trustverify.py verify-signature -m metadata.json -s metadata.sig -k public_key.pem

7. Full verification (recommended)
python trustverify.py verify test_data -m metadata.json -s metadata.sig -k public_key.pem

🧪 Demo Scenario
Create a manifest
Generate RSA keys
Sign the manifest
Run verification → ✅ Success
Modify any file inside test_data/
Run verification again → ❌ Verification Failed

🔍 Key Concepts
Integrity: Ensured using SHA-256 hashing
Authenticity: Ensured using RSA digital signatures
Non-repudiation: Achieved through private/public key cryptography

📁 Project Structure
trustverify/
├── trustverify.py
├── requirements.txt
├── README.md
├── report.md
└── test_data/
    ├── sample.txt
    └── notes.txt