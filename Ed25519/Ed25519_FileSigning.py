"""
Ed25519 File Signing Module
Ký và verify signatures cho files (PDF, documents, v.v.)

Features:
- Sign any file (PDF, DOCX, images, etc.)
- Detached signatures (signature riêng biệt với file)
- Embedded signatures (signature trong file metadata)
- Batch signing multiple files
- Verify file integrity và authenticity
"""

import os
import hashlib
import json
from datetime import datetime
from .Ed25519_KeyGen import Ed25519PrivateKey, Ed25519PublicKey, generate_keypair
from .Ed25519_Sign import sign
from .Ed25519_Verify import verify


class FileSignature:
    """
    File signature với metadata
    """

    def __init__(self, filename, file_hash, signature, public_key, timestamp=None, metadata=None):
        """
        Args:
            filename: Tên file được ký
            file_hash: SHA-256 hash của file
            signature: Ed25519Signature (bytes)
            public_key: Ed25519PublicKey (bytes)
            timestamp: Thời gian ký (ISO format)
            metadata: Dict với thông tin thêm
        """
        self.filename = filename
        self.file_hash = file_hash
        self.signature = signature
        self.public_key = public_key
        self.timestamp = timestamp or datetime.now().isoformat()
        self.metadata = metadata or {}

    def to_dict(self):
        """Convert sang dictionary để serialize"""
        return {
            "filename": self.filename,
            "file_hash": self.file_hash.hex(),
            "signature": self.signature.hex(),
            "public_key": self.public_key.hex(),
            "timestamp": self.timestamp,
            "metadata": self.metadata,
            "version": "1.0"
        }

    @staticmethod
    def from_dict(data):
        """Load từ dictionary"""
        return FileSignature(
            filename=data["filename"],
            file_hash=bytes.fromhex(data["file_hash"]),
            signature=bytes.fromhex(data["signature"]),
            public_key=bytes.fromhex(data["public_key"]),
            timestamp=data.get("timestamp"),
            metadata=data.get("metadata", {})
        )

    def save(self, output_path):
        """
        Save signature ra file JSON

        Args:
            output_path: Đường dẫn file output (.sig hoặc .json)
        """
        with open(output_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)

    @staticmethod
    def load(signature_path):
        """
        Load signature từ file JSON

        Args:
            signature_path: Đường dẫn file signature
        """
        with open(signature_path, 'r') as f:
            data = json.load(f)
        return FileSignature.from_dict(data)


def hash_file(file_path, chunk_size=8192):
    """
    Tính SHA-256 hash của file

    Args:
        file_path: Đường dẫn file
        chunk_size: Kích thước chunk để đọc (bytes)

    Returns:
        bytes: SHA-256 hash (32 bytes)
    """
    sha256 = hashlib.sha256()

    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.digest()


def sign_file(file_path, private_key, output_sig_path=None, metadata=None):
    """
    Ký một file

    Process:
    1. Tính SHA-256 hash của file
    2. Ký hash với Ed25519
    3. Save signature + metadata ra file .sig

    Args:
        file_path: Đường dẫn file cần ký
        private_key: Ed25519PrivateKey hoặc bytes (32 bytes seed)
        output_sig_path: Đường dẫn file signature output (default: file_path + ".sig")
        metadata: Dict với thông tin thêm (tác giả, mô tả, v.v.)

    Returns:
        FileSignature object
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File không tồn tại: {file_path}")

    # Parse private key
    if isinstance(private_key, bytes):
        private_key = Ed25519PrivateKey(seed=private_key)

    # Tính file hash
    print(f"Computing hash for: {file_path}")
    file_hash = hash_file(file_path)
    print(f"File hash: {file_hash.hex()}")

    # Sign hash
    signature_obj = sign(file_hash, private_key)
    signature_bytes = signature_obj.to_bytes()

    # Get public key
    public_key = private_key.get_public_key()
    public_key_bytes = public_key.to_bytes()

    # Create FileSignature
    filename = os.path.basename(file_path)
    file_sig = FileSignature(
        filename=filename,
        file_hash=file_hash,
        signature=signature_bytes,
        public_key=public_key_bytes,
        metadata=metadata
    )

    # Save signature file
    if output_sig_path is None:
        output_sig_path = file_path + ".sig"

    file_sig.save(output_sig_path)
    print(f"Signature saved to: {output_sig_path}")

    return file_sig


def verify_file(file_path, signature_path=None, public_key=None):
    """
    Verify file signature

    Args:
        file_path: Đường dẫn file cần verify
        signature_path: Đường dẫn file signature (default: file_path + ".sig")
        public_key: Ed25519PublicKey hoặc bytes (nếu None, dùng key trong signature file)

    Returns:
        dict với kết quả verification:
        {
            "valid": bool,
            "message": str,
            "signature_info": dict
        }
    """
    if not os.path.exists(file_path):
        return {
            "valid": False,
            "message": f"File không tồn tại: {file_path}",
            "signature_info": None
        }

    # Load signature file
    if signature_path is None:
        signature_path = file_path + ".sig"

    if not os.path.exists(signature_path):
        return {
            "valid": False,
            "message": f"Signature file không tồn tại: {signature_path}",
            "signature_info": None
        }

    try:
        file_sig = FileSignature.load(signature_path)
    except Exception as e:
        return {
            "valid": False,
            "message": f"Không thể load signature file: {e}",
            "signature_info": None
        }

    # Tính hash của file hiện tại
    print(f"Computing hash for: {file_path}")
    current_hash = hash_file(file_path)

    # Check hash khớp không
    if current_hash != file_sig.file_hash:
        return {
            "valid": False,
            "message": "File đã bị thay đổi! Hash không khớp.",
            "signature_info": file_sig.to_dict(),
            "current_hash": current_hash.hex(),
            "expected_hash": file_sig.file_hash.hex()
        }

    # Verify signature
    if public_key is None:
        # Dùng public key từ signature file
        public_key = file_sig.public_key
    elif isinstance(public_key, Ed25519PublicKey):
        public_key = public_key.to_bytes()

    is_valid = verify(file_sig.signature, file_sig.file_hash, public_key)

    if is_valid:
        return {
            "valid": True,
            "message": "Signature hợp lệ! File chưa bị thay đổi.",
            "signature_info": file_sig.to_dict(),
            "metadata": file_sig.metadata
        }
    else:
        return {
            "valid": False,
            "message": "Signature không hợp lệ!",
            "signature_info": file_sig.to_dict(),
            "metadata": file_sig.metadata
        }


def sign_multiple_files(file_paths, private_key, output_dir=None, metadata=None):
    """
    Ký nhiều files cùng lúc

    Args:
        file_paths: List các đường dẫn file
        private_key: Ed25519PrivateKey
        output_dir: Thư mục chứa signature files (default: cùng thư mục với files)
        metadata: Metadata chung cho tất cả signatures

    Returns:
        list of FileSignature objects
    """
    signatures = []

    for file_path in file_paths:
        if output_dir:
            filename = os.path.basename(file_path)
            sig_path = os.path.join(output_dir, filename + ".sig")
        else:
            sig_path = None

        try:
            file_sig = sign_file(file_path, private_key, sig_path, metadata)
            signatures.append(file_sig)
        except Exception as e:
            print(f"Error signing {file_path}: {e}")

    return signatures




def interactive_sign():
    """Interactive mode để ký file"""
    print("=" * 70)
    print("Ed25519 File Signing - Interactive Mode")
    print("=" * 70)

    # Get file path
    file_path = input("\nEnter file path to sign: ").strip()

    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return

    # Check if keypair exists
    private_key_file = "private_key.bin"
    public_key_file = "public_key.bin"

    if os.path.exists(private_key_file):
        print("\nFound existing keypair. Loading...")
        with open(private_key_file, 'rb') as f:
            private_key = Ed25519PrivateKey.from_bytes(f.read())
        with open(public_key_file, 'rb') as f:
            public_key = Ed25519PublicKey.from_bytes(f.read())
    else:
        print("\nGenerating new keypair...")
        private_key, public_key = generate_keypair()

        # Save keypair
        with open(private_key_file, 'wb') as f:
            f.write(private_key.to_bytes())
        with open(public_key_file, 'wb') as f:
            f.write(public_key.to_bytes())
        print(f"Keypair saved to {private_key_file} and {public_key_file}")

    print(f"Public key: {public_key.to_bytes().hex()}")

    # Get metadata
    print("\nOptional metadata (press Enter to skip):")
    author = input("  Author: ").strip() or None
    description = input("  Description: ").strip() or None

    metadata = {}
    if author:
        metadata["author"] = author
    if description:
        metadata["description"] = description

    # Sign file
    print(f"\nSigning file: {file_path}")
    file_sig = sign_file(file_path, private_key, metadata=metadata)

    print("\n✓ File signed successfully!")
    print(f"Signature saved to: {file_path}.sig")
    print("\nTo verify, run:")
    print(f'  python -c "from Ed25519_FileSigning import verify_file; '
          f'print(verify_file(\'{file_path}\'))"')


def interactive_verify():
    """Interactive mode để verify file"""
    print("=" * 70)
    print("Ed25519 File Verification - Interactive Mode")
    print("=" * 70)

    # Get file path
    file_path = input("\nEnter file path to verify: ").strip()

    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return

    # Verify
    print(f"\nVerifying file: {file_path}")
    result = verify_file(file_path)

    print("\n" + "=" * 70)
    print(f"VERIFICATION RESULT: {'✓ VALID' if result['valid'] else '✗ INVALID'}")
    print("=" * 70)
    print(f"\n{result['message']}")

    if result['signature_info']:
        print("\nSignature Information:")
        info = result['signature_info']
        print(f"  Filename: {info['filename']}")
        print(f"  Signed at: {info['timestamp']}")
        print(f"  Public key: {info['public_key'][:32]}...")
        if info.get('metadata'):
            print(f"  Metadata: {info['metadata']}")


# if __name__ == "__main__":
#     private_key, public_key = generate_keypair()
#     test_file = "test_1.pdf"
#
#     metadata = {
#         "author": "Le Phe Do",
#         "department": "UET-VNU",
#         "description": "Giang vien Toan va Mat ma hoc"
#     }
#
#     file_sig = sign_file(test_file, private_key, metadata=metadata)
#     print(f"Signature info:")
#     print(f"  Filename: {file_sig.filename}")
#     print(f"  Hash: {file_sig.file_hash.hex()[:32]}...")
#     print(f"  Timestamp: {file_sig.timestamp}")
#     print(f"  Metadata: {file_sig.metadata}")
#
#     result = verify_file(test_file)
#     print(f"Valid: {result['valid']}")
#     print(f"Message: {result['message']}")