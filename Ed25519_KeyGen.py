"""
Ed25519 Key Generation Module
Triển khai tạo cặp khóa private/public key theo Ed25519 specification

Key Generation Process:
1. Generate 32 random bytes làm private key
2. Hash private key với SHA-512 → 64 bytes
3. Clamp 32 bytes đầu thành scalar 'a'
4. Public key A = a * B (B là base point)
5. Encode A thành 32 bytes

Private key: 32 bytes (seed)
Public key: 32 bytes (encoded point)
"""

import os
import secrets
import hashlib
from Ed25519_FieldArithmetic import FieldElement
from Ed25519_CurveArithmetic import EdwardsPoint, BASE_POINT, L


class Ed25519PrivateKey:
    """
    Ed25519 Private Key
    Lưu trữ 32-byte seed và các giá trị derived
    """

    def __init__(self, seed=None):
        """
        Khởi tạo private key

        Args:
            seed: 32 bytes (nếu None, sẽ generate random)
        """
        if seed is None:
            # Generate random 32 bytes
            self.seed = secrets.token_bytes(32)
        else:
            if len(seed) != 32:
                raise ValueError("Private key seed phải là 32 bytes")
            self.seed = bytes(seed)

        # Derive các giá trị từ seed
        self._derive_key_data()

    def _derive_key_data(self):
        """
        Derive scalar và prefix từ seed

        Process:
        1. h = SHA-512(seed) → 64 bytes
        2. a = clamp(h[0:32]) → scalar for public key
        3. prefix = h[32:64] → prefix for signing
        """
        # Hash seed với SHA-512
        h = hashlib.sha512(self.seed).digest()

        # 32 bytes đầu → scalar 'a'
        h_low = bytearray(h[:32])

        # Clamp scalar theo Ed25519 spec
        self.scalar_bytes = self._clamp_scalar(h_low)

        # Convert sang integer (little-endian)
        self.scalar = int.from_bytes(self.scalar_bytes, byteorder='little')

        # 32 bytes sau → prefix cho signing
        self.prefix = h[32:64]

    @staticmethod
    def _clamp_scalar(h):
        """
        Clamp scalar theo Ed25519 specification

        Clamping ensures:
        - Scalar có dạng 2^254 + 8*{0, 1, ..., 2^251-1}
        - Bits 0,1,2 = 0 (multiple của 8)
        - Bit 255 = 0 (đảm bảo < 2^255)
        - Bit 254 = 1 (đảm bảo >= 2^254)

        Operations:
        - h[0] &= 248  (clear bits 0,1,2)
        - h[31] &= 127 (clear bit 255)
        - h[31] |= 64  (set bit 254)

        Args:
            h: bytearray of 32 bytes

        Returns:
            bytes: clamped scalar
        """
        h = bytearray(h)

        # Clear bits 0, 1, 2 của byte đầu
        h[0] &= 0b11111000  # 248 = 0xF8

        # Clear bit 255 (bit cao nhất của byte cuối)
        h[31] &= 0b01111111  # 127 = 0x7F

        # Set bit 254
        h[31] |= 0b01000000  # 64 = 0x40

        return bytes(h)

    def get_public_key(self):
        """
        Derive public key từ private key
        Public key A = a * B

        Returns:
            Ed25519PublicKey
        """
        # Tính A = scalar * BASE_POINT
        A = BASE_POINT.scalar_mul(self.scalar)

        return Ed25519PublicKey(A)

    def to_bytes(self):
        """Export private key seed (32 bytes)"""
        return self.seed

    @staticmethod
    def from_bytes(data):
        """
        Import private key từ bytes

        Args:
            data: 32 bytes
        """
        return Ed25519PrivateKey(seed=data)

    def __repr__(self):
        return f"Ed25519PrivateKey(seed={self.seed.hex()[:16]}...)"


class Ed25519PublicKey:
    """
    Ed25519 Public Key
    Lưu trữ điểm A trên curve
    """

    def __init__(self, point):
        """
        Khởi tạo public key

        Args:
            point: EdwardsPoint
        """
        if not isinstance(point, EdwardsPoint):
            raise TypeError("Point phải là EdwardsPoint")

        if not point.is_on_curve():
            raise ValueError("Point không nằm trên curve")

        self.point = point

    def to_bytes(self):
        """
        Export public key (32 bytes)
        Encode point A
        """
        return self.point.encode()

    @staticmethod
    def from_bytes(data):
        """
        Import public key từ bytes

        Args:
            data: 32 bytes (encoded point)
        """
        if len(data) != 32:
            raise ValueError("Public key phải là 32 bytes")

        point = EdwardsPoint.decode(data)
        if point is None:
            raise ValueError("Invalid public key encoding")

        return Ed25519PublicKey(point)

    def __repr__(self):
        encoded = self.to_bytes()
        return f"Ed25519PublicKey({encoded.hex()[:16]}...)"

    def __eq__(self, other):
        """So sánh hai public keys"""
        if not isinstance(other, Ed25519PublicKey):
            return False
        return self.point == other.point


def generate_keypair():
    """
    Generate một cặp khóa Ed25519 mới

    Returns:
        tuple: (Ed25519PrivateKey, Ed25519PublicKey)
    """
    private_key = Ed25519PrivateKey()
    public_key = private_key.get_public_key()
    return private_key, public_key


def derive_public_key(private_key):
    """
    Derive public key từ private key

    Args:
        private_key: Ed25519PrivateKey hoặc 32 bytes

    Returns:
        Ed25519PublicKey
    """
    if isinstance(private_key, bytes):
        private_key = Ed25519PrivateKey(seed=private_key)

    return private_key.get_public_key()


def demo_key_generation():
    """Demo sử dụng key generation"""
    print("\n" + "=" * 60)
    print("Ed25519 Key Generation Demo")
    print("=" * 60)

    # Generate new keypair
    print("\n1. Generating new keypair...")
    private_key, public_key = generate_keypair()

    print(f"\nPrivate Key (seed):")
    print(f"  Hex: {private_key.to_bytes().hex()}")
    print(f"  Length: {len(private_key.to_bytes())} bytes")

    print(f"\nScalar (clamped):")
    print(f"  Hex: {private_key.scalar_bytes.hex()}")
    print(f"  Integer: {private_key.scalar}")
    print(f"  Bits: {private_key.scalar.bit_length()}")

    print(f"\nPublic Key:")
    print(f"  Hex: {public_key.to_bytes().hex()}")
    print(f"  Length: {len(public_key.to_bytes())} bytes")

    # Demonstrate deterministic derivation
    print("\n2. Demonstrating deterministic derivation...")
    seed = secrets.token_bytes(32)
    print(f"Seed: {seed.hex()}")

    pk1 = Ed25519PrivateKey(seed=seed)
    pk2 = Ed25519PrivateKey(seed=seed)

    pub1 = pk1.get_public_key()
    pub2 = pk2.get_public_key()

    print(f"Public Key 1: {pub1.to_bytes().hex()}")
    print(f"Public Key 2: {pub2.to_bytes().hex()}")
    print(f"Keys match: {pub1 == pub2}")

    # Demonstrate serialization
    print("\n3. Demonstrating serialization...")
    private_key, public_key = generate_keypair()

    # Save to bytes
    private_bytes = private_key.to_bytes()
    public_bytes = public_key.to_bytes()

    print(f"Original public key: {public_bytes.hex()}")

    # Load from bytes
    loaded_private = Ed25519PrivateKey.from_bytes(private_bytes)
    loaded_public = Ed25519PublicKey.from_bytes(public_bytes)

    print(f"Loaded public key:   {loaded_public.to_bytes().hex()}")
    print(f"Keys match: {public_key == loaded_public}")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    # test_key_generation()
    demo_key_generation()

    # # Generate new keypair
    # private_key, public_key = generate_keypair()
    #
    # # Save keys
    # private_bytes = private_key.to_bytes()  # 32 bytes
    # public_bytes = public_key.to_bytes()  # 32 bytes
    #
    # # Load keys
    # loaded_private = Ed25519PrivateKey.from_bytes(private_bytes)
    # loaded_public = Ed25519PublicKey.from_bytes(public_bytes)
    #
    # # Derive public from private
    # public_key = private_key.get_public_key()
    #
    # # Deterministic generation
    # seed = b'\x00' * 32
    # private_key = Ed25519PrivateKey(seed=seed)