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

import hashlib
import json
import os
from datetime import datetime

from .Ed25519_KeyGen import Ed25519PrivateKey, Ed25519PublicKey
from .Ed25519_Sign import sign
from .Ed25519_Verify import verify


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


# if __name__ == "__main__":
#     import sys
#
#     private_key, public_key = generate_keypair()
#     test_file = "test_1.pdf"
#     backup_file = test_file + ".backup"
#     shutil.copy(test_file, backup_file)
#
#     metadata = {
#         "author": "Le Phe Do",
#         "purpose": "Nhóm bài tập lớn"
#     }
#
#     signed_file = embed_signature(test_file, private_key, metadata=metadata)
#
#     result = verify_embedded_signature(signed_file)
#
#     print(f"Valid: {result['valid']}")
#     print(f"Message: {result['message']}")
