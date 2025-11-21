"""
Ed25519 Embedded Signature Module
Nhúng chữ ký trực tiếp vào file thay vì tạo file .sig riêng

So sánh:
- Detached Signature: file.pdf + file.pdf.sig (2 files riêng biệt)
- Embedded Signature: file.pdf (signature nhúng trong metadata/footer)

Advantages:
- Chỉ cần 1 file duy nhất
- Không lo mất file signature
- Dễ distribute và share

Disadvantages:
- Phải modify file gốc
- Không phải format nào cũng support
- Tăng kích thước file một chút
"""

import os
import json
import hashlib
import shutil
from datetime import datetime
from Ed25519_KeyGen import Ed25519PrivateKey, Ed25519PublicKey, generate_keypair
from Ed25519_Sign import sign
from Ed25519_Verify import verify
from Ed25519_FileSigning import hash_file


class EmbeddedSignatureFormat:
    """
    Format cho embedded signature

    Structure:
    ┌─────────────────────────────┐
    │   Original File Content     │
    │   (binary data)             │
    ├─────────────────────────────┤
    │   SIGNATURE MARKER          │  ← "===ED25519_SIGNATURE==="
    ├─────────────────────────────┤
    │   Signature JSON            │  ← {signature, public_key, ...}
    │   (base64 encoded)          │
    ├─────────────────────────────┤
    │   END MARKER                │  ← "===END_SIGNATURE==="
    └─────────────────────────────┘
    """

    SIGNATURE_MARKER = b"\n===ED25519_SIGNATURE===\n"
    END_MARKER = b"\n===END_SIGNATURE===\n"

    @staticmethod
    def has_signature(file_path):
        """
        Check xem file có embedded signature không

        Args:
            file_path: Đường dẫn file

        Returns:
            bool: True nếu có signature
        """
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            return EmbeddedSignatureFormat.SIGNATURE_MARKER in content
        except:
            return False

    @staticmethod
    def split_content_and_signature(file_data):
        """
        Tách original content và signature data

        Args:
            file_data: bytes của file

        Returns:
            tuple: (original_content, signature_json_str) hoặc (file_data, None)
        """
        if EmbeddedSignatureFormat.SIGNATURE_MARKER not in file_data:
            return file_data, None

        # Tìm vị trí markers
        sig_start = file_data.find(EmbeddedSignatureFormat.SIGNATURE_MARKER)
        sig_end = file_data.find(EmbeddedSignatureFormat.END_MARKER)

        if sig_start == -1 or sig_end == -1:
            return file_data, None

        # Extract original content (trước signature marker)
        original_content = file_data[:sig_start]

        # Extract signature JSON (giữa markers)
        sig_json_start = sig_start + len(EmbeddedSignatureFormat.SIGNATURE_MARKER)
        sig_json_bytes = file_data[sig_json_start:sig_end]
        sig_json_str = sig_json_bytes.decode('utf-8')

        return original_content, sig_json_str


def embed_signature(file_path, private_key, output_path=None, metadata=None):
    """
    Nhúng signature vào file

    Process:
    1. Đọc original file content
    2. Tính hash của original content
    3. Sign hash
    4. Append signature vào cuối file
    5. Save signed file

    Args:
        file_path: Đường dẫn file gốc
        private_key: Ed25519PrivateKey hoặc bytes
        output_path: Đường dẫn output (default: overwrite file gốc)
        metadata: Dict metadata

    Returns:
        str: Path của signed file
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File không tồn tại: {file_path}")

    # Parse private key
    if isinstance(private_key, bytes):
        private_key = Ed25519PrivateKey(seed=private_key)

    # Đọc original content
    print(f"Reading file: {file_path}")
    with open(file_path, 'rb') as f:
        original_content = f.read()

    # Check xem đã có signature chưa
    if EmbeddedSignatureFormat.has_signature(file_path):
        print("File already has embedded signature. Removing old signature...")
        original_content, _ = EmbeddedSignatureFormat.split_content_and_signature(original_content)

    # Tính hash của original content
    file_hash = hashlib.sha256(original_content).digest()
    print(f"Content hash: {file_hash.hex()}")

    # Sign hash
    signature_obj = sign(file_hash, private_key)
    signature_bytes = signature_obj.to_bytes()

    # Get public key
    public_key = private_key.get_public_key()
    public_key_bytes = public_key.to_bytes()

    # Create signature metadata
    sig_data = {
        "filename": os.path.basename(file_path),
        "file_size": len(original_content),
        "file_hash": file_hash.hex(),
        "signature": signature_bytes.hex(),
        "public_key": public_key_bytes.hex(),
        "timestamp": datetime.now().isoformat(),
        "metadata": metadata or {},
        "version": "1.0"
    }

    # Convert to JSON
    sig_json = json.dumps(sig_data, indent=2)

    # Build signed file content
    signed_content = (
            original_content +
            EmbeddedSignatureFormat.SIGNATURE_MARKER +
            sig_json.encode('utf-8') +
            EmbeddedSignatureFormat.END_MARKER
    )

    # Save
    if output_path is None:
        output_path = file_path

    with open(output_path, 'wb') as f:
        f.write(signed_content)

    print(f"Embedded signature saved to: {output_path}")
    print(f"File size: {len(original_content)} → {len(signed_content)} bytes "
          f"(+{len(signed_content) - len(original_content)} bytes)")

    return output_path


def verify_embedded_signature(file_path, public_key=None):
    """
    Verify embedded signature trong file

    Args:
        file_path: Đường dẫn file đã ký
        public_key: Ed25519PublicKey hoặc bytes (nếu None, dùng key trong file)

    Returns:
        dict: Kết quả verification
    """
    if not os.path.exists(file_path):
        return {
            "valid": False,
            "message": f"File không tồn tại: {file_path}",
            "signature_info": None
        }

    # Đọc file
    with open(file_path, 'rb') as f:
        file_data = f.read()

    # Check có signature không
    if not EmbeddedSignatureFormat.has_signature(file_path):
        return {
            "valid": False,
            "message": "File không có embedded signature",
            "signature_info": None
        }

    # Split content và signature
    original_content, sig_json_str = EmbeddedSignatureFormat.split_content_and_signature(file_data)

    if sig_json_str is None:
        return {
            "valid": False,
            "message": "Không thể parse embedded signature",
            "signature_info": None
        }

    # Parse signature JSON
    try:
        sig_data = json.loads(sig_json_str)
    except Exception as e:
        return {
            "valid": False,
            "message": f"Signature JSON không hợp lệ: {e}",
            "signature_info": None
        }

    # Tính hash của original content
    print(f"Computing hash of original content...")
    current_hash = hashlib.sha256(original_content).digest()
    stored_hash = bytes.fromhex(sig_data['file_hash'])

    # Check hash
    if current_hash != stored_hash:
        return {
            "valid": False,
            "message": "Content đã bị thay đổi! Hash không khớp.",
            "signature_info": sig_data,
            "current_hash": current_hash.hex(),
            "expected_hash": stored_hash.hex()
        }

    # Verify signature
    signature_bytes = bytes.fromhex(sig_data['signature'])

    if public_key is None:
        # Dùng public key từ signature
        public_key = bytes.fromhex(sig_data['public_key'])
    elif isinstance(public_key, Ed25519PublicKey):
        public_key = public_key.to_bytes()

    is_valid = verify(signature_bytes, stored_hash, public_key)

    if is_valid:
        return {
            "valid": True,
            "message": "Embedded signature hợp lệ! Content chưa bị thay đổi.",
            "signature_info": sig_data,
            "original_size": len(original_content)
        }
    else:
        return {
            "valid": False,
            "message": "Signature không hợp lệ!",
            "signature_info": sig_data
        }


def extract_original_file(signed_file_path, output_path=None):
    """
    Extract file gốc (bỏ embedded signature)

    Args:
        signed_file_path: Đường dẫn file đã ký
        output_path: Đường dẫn output (default: signed_file_path + ".original")

    Returns:
        str: Path của file gốc
    """
    if not os.path.exists(signed_file_path):
        raise FileNotFoundError(f"File không tồn tại: {signed_file_path}")

    # Đọc file
    with open(signed_file_path, 'rb') as f:
        file_data = f.read()

    # Split
    original_content, sig_json = EmbeddedSignatureFormat.split_content_and_signature(file_data)

    if sig_json is None:
        print("File không có embedded signature, không cần extract.")
        return signed_file_path

    # Save original
    if output_path is None:
        base, ext = os.path.splitext(signed_file_path)
        output_path = f"{base}.original{ext}"

    with open(output_path, 'wb') as f:
        f.write(original_content)

    print(f"Original file extracted to: {output_path}")
    print(f"Size: {len(file_data)} → {len(original_content)} bytes")

    return output_path


def demo_embedded_signature():
    """Demo embedded signature"""
    print("=" * 70)
    print("Embedded Signature Demo")
    print("=" * 70)

    from Ed25519_KeyGen import generate_keypair
    import shutil

    # 1. Generate keypair
    print("\n1. Generating keypair...")
    private_key, public_key = generate_keypair()
    print(f"Public key: {public_key.to_bytes().hex()[:32]}...")

    # 2. Create test file
    print("\n2. Creating test file...")
    test_file = "test_embedded.txt"
    with open(test_file, 'w') as f:
        f.write("This is the original content.\n")
        f.write("It will have an embedded signature.\n")
        f.write("The signature is appended at the end.\n")

    original_size = os.path.getsize(test_file)
    print(f"Created: {test_file} ({original_size} bytes)")

    # Create backup for later verification
    backup_file = test_file + ".backup"
    shutil.copy(test_file, backup_file)

    # 3. Embed signature
    print("\n3. Embedding signature...")
    metadata = {
        "author": "Alice",
        "purpose": "Test embedded signature"
    }

    signed_file = embed_signature(test_file, private_key, metadata=metadata)
    signed_size = os.path.getsize(signed_file)

    print(f"\n✓ Signature embedded successfully!")
    print(f"File size: {original_size} → {signed_size} bytes (+{signed_size - original_size})")

    # 4. Verify embedded signature
    print("\n4. Verifying embedded signature...")
    result = verify_embedded_signature(signed_file)

    print(f"Valid: {result['valid']}")
    print(f"Message: {result['message']}")
    if result['signature_info']:
        print(f"Signed by: {result['signature_info']['metadata']['author']}")
        print(f"Signed at: {result['signature_info']['timestamp']}")

    # 5. Extract original file
    print("\n5. Extracting original file...")
    original_extracted = extract_original_file(signed_file)

    # Verify extracted file matches original
    with open(backup_file, 'rb') as f:
        original_backup = f.read()
    with open(original_extracted, 'rb') as f:
        extracted = f.read()

    if original_backup == extracted:
        print("✓ Extracted file matches original!")
    else:
        print("✗ Extracted file does NOT match original!")

    # 6. Demonstrate tampering detection
    print("\n6. Testing tampering detection...")
    print("Modifying signed file content...")

    with open(signed_file, 'rb') as f:
        tampered = f.read()

    # Modify content (insert text near beginning)
    tampered = tampered[:50] + b"TAMPERED" + tampered[50:]

    with open(signed_file, 'wb') as f:
        f.write(tampered)

    result = verify_embedded_signature(signed_file)
    print(f"Valid: {result['valid']}")
    print(f"Message: {result['message']}")

    # 7. Cleanup
    print("\n7. Cleaning up...")
    files_to_remove = [test_file, backup_file, original_extracted]
    for file in files_to_remove:
        if os.path.exists(file):
            os.remove(file)
            print(f"Removed: {file}")
    print("Test files removed.")

    print("\n" + "=" * 70)

def compare_detached_vs_embedded():
    """So sánh Detached vs Embedded signatures"""
    print("=" * 70)
    print("Detached vs Embedded Signatures Comparison")
    print("=" * 70)

    comparison = """

╔═══════════════════════╦═════════════════════════╦══════════════════════════╗
║      Feature          ║   Detached Signature    ║   Embedded Signature     ║
╠═══════════════════════╬═════════════════════════╬══════════════════════════╣
║ Number of files       ║ 2 files                 ║ 1 file                   ║
║                       ║ (file + file.sig)       ║ (signature inside)       ║
╠═══════════════════════╬═════════════════════════╬══════════════════════════╣
║ File modification     ║ ✗ No modification       ║ ✓ Modifies original      ║
║                       ║ Original stays intact   ║ Appends signature        ║
╠═══════════════════════╬═════════════════════════╬══════════════════════════╣
║ Distribution          ║ Must send both files    ║ Send single file         ║
║                       ║ Risk: lose .sig file    ║ Everything in one        ║
╠═══════════════════════╬═════════════════════════╬══════════════════════════╣
║ File format support   ║ ✓ Works with any format ║ ⚠ Text/binary formats   ║
║                       ║ PDF, EXE, ZIP, etc.     ║ May not work with all    ║
╠═══════════════════════╬═════════════════════════╬══════════════════════════╣
║ File size increase    ║ Separate .sig file      ║ +300-500 bytes           ║
║                       ║ (~300 bytes)            ║ (appended to file)       ║
╠═══════════════════════╬═════════════════════════╬══════════════════════════╣
║ Verification          ║ Need both files         ║ Single file is enough    ║
╠═══════════════════════╬═════════════════════════╬══════════════════════════╣
║ Use cases             ║ • Software releases     ║ • Documents              ║
║                       ║ • Official documents    ║ • Text files             ║
║                       ║ • When original must    ║ • Configuration files    ║
║                       ║   stay untouched        ║ • Self-contained files   ║
╠═══════════════════════╬═════════════════════════╬══════════════════════════╣
║ Advantages            ║ ✓ No file modification  ║ ✓ Single file            ║
║                       ║ ✓ Any file format       ║ ✓ Can't lose signature   ║
║                       ║ ✓ Clear separation      ║ ✓ Easy distribution      ║
╠═══════════════════════╬═════════════════════════╬══════════════════════════╣
║ Disadvantages         ║ ✗ Two files to manage   ║ ✗ Modifies original      ║
║                       ║ ✗ Can lose .sig file    ║ ✗ Format limitations     ║
║                       ║ ✗ Must send both        ║ ✗ Slightly larger        ║
╚═══════════════════════╩═════════════════════════╩══════════════════════════╝

RECOMMENDATIONS:

1. Use DETACHED when:
   ✓ Original file must not be modified (legal docs, executables)
   ✓ Working with binary formats (PDF, EXE, images)
   ✓ Need to verify without extracting
   ✓ Industry standard requires separate signature

2. Use EMBEDDED when:
   ✓ Convenience is priority (single file)
   ✓ Text-based formats (config, source code, documents)
   ✓ Easy distribution needed
   ✓ Won't lose signature file

3. Use BOTH when:
   ✓ Maximum flexibility needed
   ✓ Different audiences prefer different methods
   ✓ Compliance requires both
"""
    print(comparison)


if __name__ == "__main__":
    import sys

    # if len(sys.argv) > 1:
    #     command = sys.argv[1].lower()
    #
    #     if command == "demo":
    #         demo_embedded_signature()
    #     elif command == "compare":
    #         compare_detached_vs_embedded()
    #     elif command == "embed":
    #         if len(sys.argv) < 3:
    #             print("Usage: python Ed25519_EmbeddedSignature.py embed <file_path>")
    #         else:
    #             from Ed25519_KeyGen import generate_keypair
    #
    #             file_path = sys.argv[2]
    #
    #             # Generate or load keypair
    #             private_key, _ = generate_keypair()
    #             embed_signature(file_path, private_key)
    #     elif command == "verify":
    #         if len(sys.argv) < 3:
    #             print("Usage: python Ed25519_EmbeddedSignature.py verify <file_path>")
    #         else:
    #             file_path = sys.argv[2]
    #             result = verify_embedded_signature(file_path)
    #             print(f"\nValid: {result['valid']}")
    #             print(f"Message: {result['message']}")
    #     elif command == "extract":
    #         if len(sys.argv) < 3:
    #             print("Usage: python Ed25519_EmbeddedSignature.py extract <file_path>")
    #         else:
    #             file_path = sys.argv[2]
    #             extract_original_file(file_path)
    #     else:
    #         print("Usage:")
    #         print("  python Ed25519_EmbeddedSignature.py demo     - Run demo")
    #         print("  python Ed25519_EmbeddedSignature.py compare  - Compare detached vs embedded")
    #         print("  python Ed25519_EmbeddedSignature.py embed <file>   - Embed signature")
    #         print("  python Ed25519_EmbeddedSignature.py verify <file>  - Verify signature")
    #         print("  python Ed25519_EmbeddedSignature.py extract <file> - Extract original")
    # else:
    #     demo_embedded_signature()
    #     print("\n")
    #     compare_detached_vs_embedded()

    private_key, public_key = generate_keypair()
    test_file = "test_1.pdf"
    backup_file = test_file + ".backup"
    shutil.copy(test_file, backup_file)

    metadata = {
        "author": "Le Phe Do",
        "purpose": "Nhóm bài tập lớn"
    }

    signed_file = embed_signature(test_file, private_key, metadata=metadata)

    result = verify_embedded_signature(signed_file)

    print(f"Valid: {result['valid']}")
    print(f"Message: {result['message']}")
