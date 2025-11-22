"""
Ed25519 Signature Generation Module
Triển khai ký message theo Ed25519 specification

Signature Process:
1. r = H(prefix || M) mod l
2. R = r * B (sử dụng precomputed table)
3. k = H(R || A || M) mod l
4. S = (r + k*a) mod l
5. Signature = R || S (64 bytes)

Features:
- Deterministic signatures (no per-message randomness)
- Fast signing với precomputed tables
- Radix-16 representation cho scalar multiplication
"""

import hashlib

from .Ed25519_CurveArithmetic import EdwardsPoint, BASE_POINT, L
from .Ed25519_KeyGen import Ed25519PrivateKey


class Ed25519Signature:
    """
    Ed25519 Signature
    Format: R (32 bytes) || S (32 bytes) = 64 bytes total
    """

    def __init__(self, R, S):
        """
        Khởi tạo signature

        Args:
            R: EdwardsPoint
            S: integer (scalar)
        """
        if not isinstance(R, EdwardsPoint):
            raise TypeError("R phải là EdwardsPoint")

        if not isinstance(S, int):
            raise TypeError("S phải là integer")

        self.R = R
        self.S = S % L  # Đảm bảo S < l

    def to_bytes(self):
        """
        Serialize signature thành 64 bytes
        Format: R_encoded (32 bytes) || S (32 bytes little-endian)
        """
        R_bytes = self.R.encode()
        S_bytes = self.S.to_bytes(32, byteorder='little')
        return R_bytes + S_bytes

    @staticmethod
    def from_bytes(data):
        """
        Deserialize signature từ 64 bytes

        Args:
            data: 64 bytes
        """
        if len(data) != 64:
            raise ValueError("Signature phải là 64 bytes")

        # Parse R (32 bytes đầu)
        R_bytes = data[:32]
        R = EdwardsPoint.decode(R_bytes)
        if R is None:
            raise ValueError("Invalid R encoding")

        # Parse S (32 bytes sau)
        S_bytes = data[32:64]
        S = int.from_bytes(S_bytes, byteorder='little')

        # Check S < l
        if S >= L:
            raise ValueError("S phải < l")

        return Ed25519Signature(R, S)

    def __repr__(self):
        sig_bytes = self.to_bytes()
        return f"Ed25519Signature({sig_bytes.hex()[:32]}...)"

    def __eq__(self, other):
        if not isinstance(other, Ed25519Signature):
            return False
        return self.R == other.R and self.S == other.S


class PrecomputedTable:
    """
    Bảng precomputed cho fixed-base scalar multiplication
    Sử dụng radix-16 với 8 multiples

    Lưu trữ: [16^i * B for i in [0,2,4,...,62]]
    Mỗi entry có 8 multiples: [1P, 2P, ..., 8P]
    """

    def __init__(self, base_point):
        """
        Tạo precomputed table cho base_point

        Args:
            base_point: EdwardsPoint
        """
        self.table = []

        # Tạo table cho 64 positions (radix-16, 256 bits / 4 bits = 64 digits)
        current = base_point

        for i in range(64):
            # Tạo 8 multiples: [1*current, 2*current, ..., 8*current]
            multiples = []
            temp = current
            for j in range(1, 9):
                multiples.append(temp)
                if j < 8:
                    temp = temp.add(current)

            self.table.append(multiples)

            # Nhân current với 16 cho iteration tiếp theo
            for _ in range(4):  # 16 = 2^4
                current = current.double()

    def scalar_mul(self, scalar):
        """
        Nhân scalar với base point sử dụng precomputed table

        Args:
            scalar: integer

        Returns:
            EdwardsPoint: scalar * base_point
        """
        if scalar == 0:
            return EdwardsPoint.zero()

        # Convert scalar sang radix-16 representation
        # scalar = r_0 + 16*r_1 + 16^2*r_2 + ... với r_i ∈ {-8,...,8}
        digits = self._scalar_to_radix16(scalar)

        # Tính tổng: Σ r_i * 16^i * B
        result = EdwardsPoint.zero()

        for i in range(len(digits)):
            if digits[i] == 0:
                continue

            # Lấy |r_i| * 16^i * B từ table
            abs_digit = abs(digits[i])

            if i >= len(self.table):
                break

            point = self.table[i][abs_digit - 1]  # -1 vì index từ 0

            # Nếu digit âm, negate point
            if digits[i] < 0:
                point = point.neg()

            # Cộng vào result
            result = result.add(point)

        return result

    @staticmethod
    def _scalar_to_radix16(scalar):
        """
        Convert scalar sang signed radix-16 representation
        Mỗi digit ∈ {-8, -7, ..., 0, ..., 7, 8}

        Args:
            scalar: integer

        Returns:
            list of integers (digits)
        """
        digits = []
        carry = 0

        # Convert sang radix-16 với signed digits
        for i in range(64):  # 256 bits / 4 bits = 64 digits
            # Lấy 4 bits tiếp theo + carry
            digit = (scalar & 0xF) + carry
            scalar >>= 4
            carry = 0

            # Convert sang signed: nếu digit > 8, chuyển thành âm
            if digit > 8:
                digit -= 16
                carry = 1  # Propagate carry

            digits.append(digit)

        return digits


# Global precomputed table cho BASE_POINT
_BASE_POINT_TABLE = None


def get_base_point_table():
    """Lấy hoặc tạo precomputed table cho BASE_POINT"""
    global _BASE_POINT_TABLE
    if _BASE_POINT_TABLE is None:
        print("Generating precomputed table for BASE_POINT...")
        _BASE_POINT_TABLE = PrecomputedTable(BASE_POINT)
        print("Precomputed table ready!")
    return _BASE_POINT_TABLE


def sign(message, private_key):
    """
    Ký message với private key

    Process:
    1. r = H(prefix || message) mod l
    2. R = r * B
    3. k = H(R || A || message) mod l
    4. S = (r + k*a) mod l
    5. Return (R, S)

    Args:
        message: bytes
        private_key: Ed25519PrivateKey

    Returns:
        Ed25519Signature
    """
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key phải là Ed25519PrivateKey")

    if not isinstance(message, bytes):
        raise TypeError("message phải là bytes")

    # Get public key
    public_key = private_key.get_public_key()
    A_bytes = public_key.to_bytes()

    # Step 1: Compute r = H(prefix || message) mod l
    r_hash = hashlib.sha512(private_key.prefix + message).digest()
    r = int.from_bytes(r_hash, byteorder='little') % L

    # Step 2: Compute R = r * B (sử dụng precomputed table)
    table = get_base_point_table()
    R = table.scalar_mul(r)
    R_bytes = R.encode()

    # Step 3: Compute k = H(R || A || message) mod l
    k_hash = hashlib.sha512(R_bytes + A_bytes + message).digest()
    k = int.from_bytes(k_hash, byteorder='little') % L

    # Step 4: Compute S = (r + k*a) mod l
    S = (r + k * private_key.scalar) % L

    # Step 5: Return signature
    return Ed25519Signature(R, S)


def sign_with_scalar_mul(message, private_key):
    """
    Ký message KHÔNG dùng precomputed table (cho testing/comparison)
    Sử dụng scalar multiplication thông thường

    Args:
        message: bytes
        private_key: Ed25519PrivateKey

    Returns:
        Ed25519Signature
    """
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("private_key phải là Ed25519PrivateKey")

    public_key = private_key.get_public_key()
    A_bytes = public_key.to_bytes()

    # Step 1: r = H(prefix || message) mod l
    r_hash = hashlib.sha512(private_key.prefix + message).digest()
    r = int.from_bytes(r_hash, byteorder='little') % L

    # Step 2: R = r * B (KHÔNG dùng table)
    R = BASE_POINT.scalar_mul(r)
    R_bytes = R.encode()

    # Step 3: k = H(R || A || message) mod l
    k_hash = hashlib.sha512(R_bytes + A_bytes + message).digest()
    k = int.from_bytes(k_hash, byteorder='little') % L

    # Step 4: S = (r + k*a) mod l
    S = (r + k * private_key.scalar) % L

    return Ed25519Signature(R, S)

def benchmark_signing():
    """Benchmark signing performance"""
    print("\n" + "="*60)
    print("Signature Generation Benchmark")
    print("="*60)

    from Ed25519_KeyGen import generate_keypair
    import time

    private_key, _ = generate_keypair()
    message = b"Benchmark message"

    # Warm up
    for _ in range(10):
        sign(message, private_key)

    # Benchmark với precomputed table
    n_iterations = 100
    start = time.time()
    for _ in range(n_iterations):
        sign(message, private_key)
    elapsed = time.time() - start

    print(f"\nWith Precomputed Table:")
    print(f"  Total time: {elapsed:.4f} seconds")
    print(f"  Per signature: {elapsed/n_iterations*1000:.2f} ms")
    print(f"  Signatures/sec: {n_iterations/elapsed:.2f}")

    # Benchmark KHÔNG dùng precomputed table
    n_iterations_slow = 10
    start = time.time()
    for _ in range(n_iterations_slow):
        sign_with_scalar_mul(message, private_key)
    elapsed_slow = time.time() - start

    print(f"\nWithout Precomputed Table:")
    print(f"  Total time: {elapsed_slow:.4f} seconds")
    print(f"  Per signature: {elapsed_slow/n_iterations_slow*1000:.2f} ms")
    print(f"  Signatures/sec: {n_iterations_slow/elapsed_slow:.2f}")

    speedup = (elapsed_slow/n_iterations_slow) / (elapsed/n_iterations)
    print(f"\nSpeedup: {speedup:.2f}x faster with precomputed table")

    print("="*60)


# if __name__ == "__main__":
#     from Ed25519_KeyGen import generate_keypair
#
#     private_key, public_key = generate_keypair()
#     print(f"Public key: {public_key.to_bytes().hex()}")
#
#     message = b"Hello, Ed25519! This is a test message."
#     print(f"Message: {message.decode()}")
#
#     signature = sign(message, private_key)
#     sig_bytes = signature.to_bytes()
#     print(f"  R: {sig_bytes[:32].hex()}")
#     print(f"  S: {sig_bytes[32:].hex()}")
