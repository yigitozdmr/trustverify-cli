import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def sha256_file(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iter_files(directory: Path):
    excluded_names = {
        "metadata.json",
        "metadata.sig",
        "private_key.pem",
        "public_key.pem",
        ".DS_Store",
    }
    files = []
    for path in directory.rglob("*"):
        if path.is_file() and path.name not in excluded_names:
            files.append(path)
    return sorted(files, key=lambda p: str(p).lower())


def create_manifest(directory: Path, output: Path):
    if not directory.is_dir():
        raise ValueError(f"Directory not found: {directory}")

    files_data = []
    for file_path in iter_files(directory):
        rel_path = file_path.relative_to(directory).as_posix()
        files_data.append({
            "filename": rel_path,
            "sha256": sha256_file(file_path)
        })

    manifest = {
        "tool": "TrustVerify",
        "algorithm": "SHA-256",
        "directory": directory.resolve().as_posix(),
        "file_count": len(files_data),
        "files": files_data,
    }

    with output.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    return manifest


def load_manifest(manifest_path: Path):
    with manifest_path.open("r", encoding="utf-8") as f:
        return json.load(f)


def check_integrity(directory: Path, manifest_path: Path) -> int:
    manifest = load_manifest(manifest_path)
    expected = {item["filename"]: item["sha256"] for item in manifest.get("files", [])}
    current = {}

    for file_path in iter_files(directory):
        rel_path = file_path.relative_to(directory).as_posix()
        current[rel_path] = sha256_file(file_path)

    missing = []
    modified = []
    new_files = []

    for fname, expected_hash in expected.items():
        if fname not in current:
            missing.append(fname)
        elif current[fname] != expected_hash:
            modified.append(fname)

    for fname in current:
        if fname not in expected:
            new_files.append(fname)

    print("\n=== Integrity Check Report ===")
    if not missing and not modified and not new_files:
        print("All files match metadata.json")
        return 0

    if missing:
        print("\nMissing files:")
        for f in missing:
            print(f"  - {f}")

    if modified:
        print("\nModified files:")
        for f in modified:
            print(f"  - {f}")

    if new_files:
        print("\nUnexpected new files:")
        for f in new_files:
            print(f"  - {f}")

    return 1


def generate_keys(private_key_path: Path, public_key_path: Path, key_size: int = 2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_key_path.write_bytes(private_bytes)
    public_key_path.write_bytes(public_bytes)

    print(f"Private key saved to: {private_key_path}")
    print(f"Public key saved to:  {public_key_path}")


def sign_manifest(manifest_path: Path, private_key_path: Path, signature_path: Path):
    manifest_bytes = manifest_path.read_bytes()
    manifest_hash_hex = sha256_bytes(manifest_bytes).encode("utf-8")

    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(),
        password=None
    )

    signature = private_key.sign(
        manifest_hash_hex,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    signature_path.write_text(
        base64.b64encode(signature).decode("utf-8"),
        encoding="utf-8"
    )
    print(f"Signature saved to: {signature_path}")
    print(f"Manifest SHA-256: {manifest_hash_hex.decode('utf-8')}")


def verify_signature(manifest_path: Path, signature_path: Path, public_key_path: Path) -> bool:
    manifest_bytes = manifest_path.read_bytes()
    manifest_hash_hex = sha256_bytes(manifest_bytes).encode("utf-8")
    signature = base64.b64decode(signature_path.read_text(encoding="utf-8"))

    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())

    try:
        public_key.verify(
            signature,
            manifest_hash_hex,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        print("Signature verification: SUCCESS")
        print(f"Manifest SHA-256: {manifest_hash_hex.decode('utf-8')}")
        return True
    except Exception:
        print("Signature verification: FAILED")
        return False


def full_verify(directory: Path, manifest_path: Path, signature_path: Path, public_key_path: Path) -> int:
    print("\n=== Step 1: Verifying signature ===")
    sig_ok = verify_signature(manifest_path, signature_path, public_key_path)

    print("\n=== Step 2: Checking directory integrity ===")
    integrity_code = check_integrity(directory, manifest_path)

    if sig_ok and integrity_code == 0:
        print("\nFINAL RESULT: Verification Successful")
        return 0
    else:
        print("\nFINAL RESULT: Verification Failed")
        return 1


def build_parser():
    parser = argparse.ArgumentParser(
        prog="trustverify.py",
        description="TrustVerify - A CLI Tool for File Integrity and Digital Signatures",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p_hash = subparsers.add_parser("hash", help="Generate SHA-256 hash for a single file")
    p_hash.add_argument("file", type=Path)

    p_manifest = subparsers.add_parser("manifest", help="Generate metadata.json for a directory")
    p_manifest.add_argument("directory", type=Path)
    p_manifest.add_argument("-o", "--output", type=Path, default=Path("metadata.json"))

    p_check = subparsers.add_parser("check", help="Compare current directory state against metadata.json")
    p_check.add_argument("directory", type=Path)
    p_check.add_argument("-m", "--manifest", type=Path, default=Path("metadata.json"))

    p_keys = subparsers.add_parser("genkeys", help="Generate RSA key pair")
    p_keys.add_argument("--private", type=Path, default=Path("private_key.pem"))
    p_keys.add_argument("--public", type=Path, default=Path("public_key.pem"))
    p_keys.add_argument("--keysize", type=int, default=2048)

    p_sign = subparsers.add_parser("sign", help="Sign metadata.json with private key")
    p_sign.add_argument("-m", "--manifest", type=Path, default=Path("metadata.json"))
    p_sign.add_argument("-k", "--key", type=Path, default=Path("private_key.pem"))
    p_sign.add_argument("-s", "--signature", type=Path, default=Path("metadata.sig"))

    p_sigverify = subparsers.add_parser("verify-signature", help="Verify metadata.json signature using public key")
    p_sigverify.add_argument("-m", "--manifest", type=Path, default=Path("metadata.json"))
    p_sigverify.add_argument("-s", "--signature", type=Path, default=Path("metadata.sig"))
    p_sigverify.add_argument("-k", "--key", type=Path, default=Path("public_key.pem"))

    p_verify = subparsers.add_parser("verify", help="Verify signature + directory integrity")
    p_verify.add_argument("directory", type=Path)
    p_verify.add_argument("-m", "--manifest", type=Path, default=Path("metadata.json"))
    p_verify.add_argument("-s", "--signature", type=Path, default=Path("metadata.sig"))
    p_verify.add_argument("-k", "--key", type=Path, default=Path("public_key.pem"))

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "hash":
            print(sha256_file(args.file))

        elif args.command == "manifest":
            manifest = create_manifest(args.directory, args.output)
            print(f"Manifest created: {args.output}")
            print(f"Files included: {manifest['file_count']}")

        elif args.command == "check":
            sys.exit(check_integrity(args.directory, args.manifest))

        elif args.command == "genkeys":
            generate_keys(args.private, args.public, args.keysize)

        elif args.command == "sign":
            sign_manifest(args.manifest, args.key, args.signature)

        elif args.command == "verify-signature":
            ok = verify_signature(args.manifest, args.signature, args.key)
            sys.exit(0 if ok else 1)

        elif args.command == "verify":
            sys.exit(full_verify(args.directory, args.manifest, args.signature, args.key))

    except FileNotFoundError as e:
        print(f"Error: file not found -> {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()