"""
Ed25519 Multi-Signature Module
Hỗ trợ nhiều người ký cùng một document/file

Concepts:
1. Sequential Multi-Signature: Ký lần lượt (A → B → C)
2. Threshold Multi-Signature: M-of-N (cần ít nhất M/N signatures)
3. Independent Multi-Signature: Mỗi người ký độc lập

Use Cases:
- Legal contracts: Cần nhiều bên ký
- Corporate approvals: Manager + Director phải ký
- Code review: Cần 2/3 reviewers approve
- Financial transactions: 2-of-3 authorization
"""

import os
import json
import hashlib
from datetime import datetime
from collections import OrderedDict
from .Ed25519_KeyGen import Ed25519PrivateKey, Ed25519PublicKey, generate_keypair
from .Ed25519_Sign import sign
from .Ed25519_Verify import verify


class Signer:
    """
    Thông tin về một signer
    """

    def __init__(self, name, email, public_key, role=None):
        """
        Args:
            name: Tên người ký
            email: Email
            public_key: Ed25519PublicKey hoặc bytes
            role: Vai trò (optional: "Manager", "Director", etc.)
        """
        self.name = name
        self.email = email

        if isinstance(public_key, bytes):
            self.public_key = Ed25519PublicKey.from_bytes(public_key)
        else:
            self.public_key = public_key

        self.role = role

    def to_dict(self):
        """Convert to dictionary"""
        return {
            "name": self.name,
            "email": self.email,
            "public_key": self.public_key.to_bytes().hex(),
            "role": self.role
        }

    @staticmethod
    def from_dict(data):
        """Load from dictionary"""
        return Signer(
            name=data["name"],
            email=data["email"],
            public_key=bytes.fromhex(data["public_key"]),
            role=data.get("role")
        )


class SignatureRecord:
    """
    Record của một signature
    """

    def __init__(self, signer, signature, timestamp=None, comment=None):
        """
        Args:
            signer: Signer object
            signature: Ed25519Signature (bytes)
            timestamp: Thời gian ký
            comment: Comment của người ký
        """
        self.signer = signer
        self.signature = signature
        self.timestamp = timestamp or datetime.now().isoformat()
        self.comment = comment

    def to_dict(self):
        """Convert to dictionary"""
        return {
            "signer": self.signer.to_dict(),
            "signature": self.signature.hex(),
            "timestamp": self.timestamp,
            "comment": self.comment
        }

    @staticmethod
    def from_dict(data):
        """Load from dictionary"""
        return SignatureRecord(
            signer=Signer.from_dict(data["signer"]),
            signature=bytes.fromhex(data["signature"]),
            timestamp=data.get("timestamp"),
            comment=data.get("comment")
        )


class MultiSignatureDocument:
    """
    Document với multi-signature

    Structure:
    - File hash
    - Required signers (danh sách người phải ký)
    - Threshold (M-of-N: cần M signatures)
    - Signature records (các signatures đã thu thập)
    - Status (pending, partial, complete)
    """

    def __init__(self, file_path, required_signers, threshold=None, metadata=None):
        """
        Args:
            file_path: Đường dẫn file cần ký
            required_signers: List of Signer objects
            threshold: Số signatures tối thiểu (None = tất cả phải ký)
            metadata: Dict metadata (title, description, etc.)
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File không tồn tại: {file_path}")

        self.file_path = file_path
        self.filename = os.path.basename(file_path)

        # Compute file hash
        self.file_hash = self._compute_file_hash()

        # Signers
        self.required_signers = required_signers
        self.threshold = threshold if threshold is not None else len(required_signers)

        if self.threshold > len(required_signers):
            raise ValueError(f"Threshold ({self.threshold}) không thể lớn hơn số signers ({len(required_signers)})")

        # Signature records
        self.signatures = OrderedDict()  # email → SignatureRecord

        # Metadata
        self.metadata = metadata or {}
        self.created_at = datetime.now().isoformat()

    def _compute_file_hash(self):
        """Tính SHA-256 hash của file"""
        sha256 = hashlib.sha256()
        with open(self.file_path, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
        return sha256.digest()

    def add_signature(self, private_key, signer_info, comment=None):
        """
        Thêm signature từ một signer

        Args:
            private_key: Ed25519PrivateKey của người ký
            signer_info: Signer object (thông tin người ký)
            comment: Comment khi ký

        Returns:
            bool: True nếu thêm thành công
        """
        # Parse private key
        if isinstance(private_key, bytes):
            private_key = Ed25519PrivateKey(seed=private_key)

        # Check xem signer có trong required list không
        signer_public_key = signer_info.public_key.to_bytes()
        is_required = False

        for required_signer in self.required_signers:
            if required_signer.public_key.to_bytes() == signer_public_key:
                is_required = True
                break

        if not is_required:
            raise ValueError(f"Signer {signer_info.name} không có trong required signers list")

        # Check xem đã ký chưa
        if signer_info.email in self.signatures:
            print(f"Warning: {signer_info.name} đã ký document này rồi. Overwriting...")

        # Sign file hash
        signature_obj = sign(self.file_hash, private_key)
        signature_bytes = signature_obj.to_bytes()

        # Verify signature (sanity check)
        is_valid = verify(signature_bytes, self.file_hash, signer_public_key)
        if not is_valid:
            raise ValueError("Signature verification failed!")

        # Add signature record
        record = SignatureRecord(
            signer=signer_info,
            signature=signature_bytes,
            comment=comment
        )

        self.signatures[signer_info.email] = record

        print(f"✓ Signature added from {signer_info.name} ({signer_info.email})")
        return True

    def verify_signature(self, email):
        """
        Verify signature của một signer cụ thể

        Args:
            email: Email của signer

        Returns:
            bool: True nếu signature hợp lệ
        """
        if email not in self.signatures:
            return False

        record = self.signatures[email]
        public_key = record.signer.public_key.to_bytes()

        return verify(record.signature, self.file_hash, public_key)

    def verify_all_signatures(self):
        """
        Verify tất cả signatures

        Returns:
            dict: {email: is_valid}
        """
        results = {}
        for email, record in self.signatures.items():
            results[email] = self.verify_signature(email)
        return results

    def is_complete(self):
        """
        Check xem document đã đủ signatures chưa

        Returns:
            bool: True nếu đủ threshold
        """
        valid_count = sum(1 for is_valid in self.verify_all_signatures().values() if is_valid)
        return valid_count >= self.threshold

    def get_status(self):
        """
        Lấy status của document

        Returns:
            dict: Status information
        """
        total_required = len(self.required_signers)
        total_signed = len(self.signatures)
        valid_count = sum(1 for is_valid in self.verify_all_signatures().values() if is_valid)

        if valid_count >= self.threshold:
            status = "complete"
        elif total_signed > 0:
            status = "partial"
        else:
            status = "pending"

        # Pending signers
        signed_emails = set(self.signatures.keys())
        required_emails = set(s.email for s in self.required_signers)
        pending_emails = required_emails - signed_emails

        return {
            "status": status,
            "threshold": self.threshold,
            "total_required": total_required,
            "total_signed": total_signed,
            "valid_signatures": valid_count,
            "pending_signers": list(pending_emails),
            "is_complete": self.is_complete()
        }

    def get_signature_chain(self):
        """
        Lấy chuỗi signatures (theo thứ tự thời gian)

        Returns:
            list: Danh sách SignatureRecord (sorted by timestamp)
        """
        records = list(self.signatures.values())
        records.sort(key=lambda r: r.timestamp)
        return records

    def to_dict(self):
        """Convert to dictionary để save"""
        return {
            "filename": self.filename,
            "file_hash": self.file_hash.hex(),
            "required_signers": [s.to_dict() for s in self.required_signers],
            "threshold": self.threshold,
            "signatures": [record.to_dict() for record in self.signatures.values()],
            "metadata": self.metadata,
            "created_at": self.created_at,
            "version": "1.0"
        }

    def save(self, output_path):
        """
        Save multi-signature document ra file JSON

        Args:
            output_path: Đường dẫn file output (.msig)
        """
        with open(output_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        print(f"Multi-signature document saved to: {output_path}")

    @staticmethod
    def load(signature_path, original_file_path):
        """
        Load multi-signature document từ file

        Args:
            signature_path: Đường dẫn file .msig
            original_file_path: Đường dẫn file gốc

        Returns:
            MultiSignatureDocument
        """
        with open(signature_path, 'r') as f:
            data = json.load(f)

        # Recreate document
        required_signers = [Signer.from_dict(s) for s in data["required_signers"]]

        doc = MultiSignatureDocument(
            file_path=original_file_path,
            required_signers=required_signers,
            threshold=data["threshold"],
            metadata=data.get("metadata", {})
        )

        # Load signatures
        for sig_data in data["signatures"]:
            record = SignatureRecord.from_dict(sig_data)
            doc.signatures[record.signer.email] = record

        doc.created_at = data.get("created_at", datetime.now().isoformat())

        return doc


def create_multisig_document(file_path, signers_info, threshold=None, metadata=None):
    """
    Tạo multi-signature document

    Args:
        file_path: Đường dẫn file cần ký
        signers_info: List of dict [{name, email, public_key, role}, ...]
        threshold: M-of-N threshold (None = all must sign)
        metadata: Document metadata

    Returns:
        MultiSignatureDocument
    """
    # Convert signers_info to Signer objects
    signers = []
    for info in signers_info:
        signer = Signer(
            name=info["name"],
            email=info["email"],
            public_key=info["public_key"],
            role=info.get("role")
        )
        signers.append(signer)

    # Create document
    doc = MultiSignatureDocument(
        file_path=file_path,
        required_signers=signers,
        threshold=threshold,
        metadata=metadata
    )

    return doc

if __name__ == "__main__":
    import sys

