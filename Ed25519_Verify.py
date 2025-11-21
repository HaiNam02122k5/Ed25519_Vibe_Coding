"""
Ed25519 Signature Verification Module
Triển khai verify signatures theo Ed25519 specification

Single Verification:
- Check: 8·S·B = 8·R + 8·k·A
- Sử dụng double-scalar multiplication
- Fast decompression cho R và A

Batch Verification (Fast):
- Verify n signatures cùng lúc
- Random linear combination
- Bos-Coster multi-scalar multiplication
- Speedup: ~5-10x cho batch size 64+
"""

import hashlib
import secrets
from Ed25519_FieldArithmetic import FieldElement
from Ed25519_CurveArithmetic import EdwardsPoint, BASE_POINT
from Ed25519_KeyGen import Ed25519PublicKey
from Ed25519_Sign import Ed25519Signature

L = 2 ** 252 + 27742317777372353535851937790883648493  # Order của base point

def verify(signature, message, public_key):
    """
    Verify một signature

    Verification equation: 8·S·B = 8·R + 8·k·A
    Trong đó: k = H(R || A || M) mod l

    Args:
        signature: Ed25519Signature hoặc 64 bytes
        message: bytes
        public_key: Ed25519PublicKey hoặc 32 bytes

    Returns:
        bool: True nếu signature hợp lệ
    """
    # Parse signature
    if isinstance(signature, bytes):
        try:
            signature = Ed25519Signature.from_bytes(signature)
        except:
            return False

    if not isinstance(signature, Ed25519Signature):
        raise TypeError("signature phải là Ed25519Signature hoặc bytes")

    # Parse public key
    if isinstance(public_key, bytes):
        try:
            public_key = Ed25519PublicKey.from_bytes(public_key)
        except:
            return False

    if not isinstance(public_key, Ed25519PublicKey):
        raise TypeError("public_key phải là Ed25519PublicKey hoặc bytes")

    # Extract R, S, A
    R = signature.R
    S = signature.S
    A = public_key.point

    # Check S < l
    if S >= L:
        return False

    # Compute k = H(R || A || M) mod l
    R_bytes = R.encode()
    A_bytes = A.encode()
    k_hash = hashlib.sha512(R_bytes + A_bytes + message).digest()
    k = int.from_bytes(k_hash, byteorder='little') % L

    # Verify: 8·S·B = 8·R + 8·k·A
    # Equivalent: S·B = R + k·A (vì cofactor = 8)
    # Hoặc: S·B - k·A - R = 0

    # Sử dụng double-scalar multiplication: S·B + k·(-A)
    # Rồi check result == R

    # Method 1: Compute left = S·B và right = R + k·A
    left = BASE_POINT.scalar_mul(S)
    right = R.add(A.scalar_mul(k))

    # Multiply by 8 (cofactor)
    for _ in range(3):  # 2^3 = 8
        left = left.double()
        right = right.double()

    return left == right


def verify_optimized(signature, message, public_key):
    """
    Verify signature với tối ưu hơn
    Sử dụng double-scalar multiplication

    Verify: S·B = R + k·A
    Tương đương: S·B - k·A = R

    Args:
        signature: Ed25519Signature
        message: bytes
        public_key: Ed25519PublicKey

    Returns:
        bool
    """
    if isinstance(signature, bytes):
        try:
            signature = Ed25519Signature.from_bytes(signature)
        except:
            return False

    if isinstance(public_key, bytes):
        try:
            public_key = Ed25519PublicKey.from_bytes(public_key)
        except:
            return False

    R = signature.R
    S = signature.S
    A = public_key.point

    if S >= L:
        return False

    # k = H(R || A || M) mod l
    k_hash = hashlib.sha512(R.encode() + A.encode() + message).digest()
    k = int.from_bytes(k_hash, byteorder='little') % L

    # Double-scalar multiplication: S·B + (-k)·A
    # Sử dụng Shamir's trick (simultaneous scalar multiplication)
    result = double_scalar_mul(S, BASE_POINT, -k % L, A)

    # Check result == R (multiply by 8 for cofactor)
    result_8 = result
    R_8 = R
    for _ in range(3):
        result_8 = result_8.double()
        R_8 = R_8.double()

    return result_8 == R_8


def double_scalar_mul(k1, P1, k2, P2):
    """
    Tính k1·P1 + k2·P2 sử dụng Shamir's trick

    Faster than computing separately:
    - Precompute P1, P2, P1+P2
    - Process both scalars simultaneously

    Args:
        k1, k2: integers (scalars)
        P1, P2: EdwardsPoint

    Returns:
        EdwardsPoint: k1·P1 + k2·P2
    """
    # Precompute combinations
    P1_plus_P2 = P1.add(P2)

    # Convert scalars to binary
    max_bits = max(k1.bit_length(), k2.bit_length())

    result = EdwardsPoint.zero()

    # Process from MSB to LSB
    for i in range(max_bits - 1, -1, -1):
        result = result.double()

        b1 = (k1 >> i) & 1
        b2 = (k2 >> i) & 1

        # Add appropriate point based on bits
        if b1 and b2:
            result = result.add(P1_plus_P2)
        elif b1:
            result = result.add(P1)
        elif b2:
            result = result.add(P2)

    return result


class BatchVerifier:
    """
    Batch verification cho nhiều signatures

    Verify n signatures (R_i, S_i) với messages M_i và public keys A_i:

    1. Chọn random z_i (128-bit)
    2. Verify: Σ z_i·S_i·B = Σ z_i·R_i + Σ z_i·k_i·A_i

    Sử dụng Bos-Coster algorithm cho multi-scalar multiplication
    """

    def __init__(self):
        self.items = []

    def add(self, signature, message, public_key):
        """
        Thêm signature vào batch

        Args:
            signature: Ed25519Signature hoặc bytes
            message: bytes
            public_key: Ed25519PublicKey hoặc bytes
        """
        # Parse inputs
        if isinstance(signature, bytes):
            signature = Ed25519Signature.from_bytes(signature)

        if isinstance(public_key, bytes):
            public_key = Ed25519PublicKey.from_bytes(public_key)

        self.items.append((signature, message, public_key))

    def verify_batch(self):
        """
        Verify tất cả signatures trong batch

        Returns:
            bool: True nếu TẤT CẢ signatures hợp lệ
        """
        if len(self.items) == 0:
            return True

        if len(self.items) == 1:
            # Fall back to single verification
            sig, msg, pk = self.items[0]
            return verify(sig, msg, pk)

        # Generate random 128-bit coefficients
        n = len(self.items)
        z_values = [secrets.randbits(128) for _ in range(n)]

        # Compute k_i = H(R_i || A_i || M_i) for all i
        k_values = []
        for sig, msg, pk in self.items:
            R_bytes = sig.R.encode()
            A_bytes = pk.point.encode()
            k_hash = hashlib.sha512(R_bytes + A_bytes + msg).digest()
            k = int.from_bytes(k_hash, byteorder='little') % L
            k_values.append(k)

        # Build multi-scalar multiplication:
        # LHS = Σ z_i·S_i·B
        # RHS = Σ z_i·R_i + Σ z_i·k_i·A_i

        # Equivalent check: LHS - RHS = 0
        # Or: (Σ z_i·S_i)·B = Σ z_i·R_i + Σ (z_i·k_i)·A_i

        scalars = []
        points = []

        # Add: (Σ z_i·S_i)·B term (negative)
        sum_zS = sum(z_values[i] * self.items[i][0].S for i in range(n)) % L
        scalars.append((-sum_zS) % L)
        points.append(BASE_POINT)

        # Add: z_i·R_i terms
        for i in range(n):
            scalars.append(z_values[i] % L)
            points.append(self.items[i][0].R)

        # Add: (z_i·k_i)·A_i terms
        for i in range(n):
            scalar = (z_values[i] * k_values[i]) % L
            scalars.append(scalar)
            points.append(self.items[i][2].point)

        # Compute multi-scalar multiplication
        result = multi_scalar_mul(scalars, points)

        # Check if result == identity (multiplied by 8)
        result_8 = result
        for _ in range(3):  # Multiply by 8
            result_8 = result_8.double()

        return result_8.is_identity()

    def verify_individually(self):
        """
        Verify từng signature riêng lẻ
        Sử dụng khi batch verification fails để tìm signature lỗi

        Returns:
            list of bool: Kết quả verify cho từng signature
        """
        results = []
        for sig, msg, pk in self.items:
            results.append(verify(sig, msg, pk))
        return results


def multi_scalar_mul(scalars, points):
    """
    Multi-scalar multiplication: Σ k_i·P_i
    Sử dụng Bos-Coster algorithm

    Args:
        scalars: list of integers
        points: list of EdwardsPoint

    Returns:
        EdwardsPoint: Σ k_i·P_i
    """
    if len(scalars) != len(points):
        raise ValueError("scalars và points phải có cùng length")

    if len(scalars) == 0:
        return EdwardsPoint.zero()

    # Bos-Coster algorithm với heap
    # Pairs: (scalar, point)
    pairs = list(zip(scalars, points))

    # Sort by scalar (descending)
    pairs.sort(key=lambda x: x[0], reverse=True)

    while len(pairs) > 1:
        # Take two largest scalars
        s1, p1 = pairs[0]
        s2, p2 = pairs[1]

        if s1 == 0:
            break

        if s2 == 0:
            # Only one non-zero scalar left
            return p1.scalar_mul(s1)

        # Replace with (s1 - s2, p1) and (s2, p1 + p2)
        pairs[0] = (s1 - s2, p1)
        pairs[1] = (s2, p1.add(p2))

        # Re-sort to maintain heap property
        pairs.sort(key=lambda x: x[0], reverse=True)

    # Final computation
    if len(pairs) == 0 or pairs[0][0] == 0:
        return EdwardsPoint.zero()

    return pairs[0][1].scalar_mul(pairs[0][0])


def batch_verify(signatures, messages, public_keys):
    """
    Verify một batch of signatures

    Args:
        signatures: list of Ed25519Signature hoặc bytes
        messages: list of bytes
        public_keys: list of Ed25519PublicKey hoặc bytes

    Returns:
        bool: True nếu TẤT CẢ signatures hợp lệ
    """
    if len(signatures) != len(messages) or len(signatures) != len(public_keys):
        raise ValueError("Lengths must match")

    verifier = BatchVerifier()
    for sig, msg, pk in zip(signatures, messages, public_keys):
        verifier.add(sig, msg, pk)

    return verifier.verify_batch()



#
#
def demo_verification():
    """Demo verification"""
    print("\n" + "="*60)
    print("Ed25519 Signature Verification Demo")
    print("="*60)

    from Ed25519_KeyGen import generate_keypair
    from Ed25519_Sign import sign

    # Generate and sign
    print("\n1. Generating keypair and signing...")
    private_key, public_key = generate_keypair()
    message = b"Important message to verify"
    signature = sign(message, private_key)

    print(f"Message: {message.decode()}")
    print(f"Signature: {signature.to_bytes().hex()[:32]}...")

    # Verify
    print("\n2. Verifying signature...")
    is_valid = verify(signature, message, public_key)
    print(f"Verification result: {is_valid}")

    # Test with wrong message
    print("\n3. Testing with wrong message...")
    wrong_msg = b"Tampered message"
    is_valid_wrong = verify(signature, wrong_msg, public_key)
    print(f"Wrong message: {wrong_msg.decode()}")
    print(f"Verification result: {is_valid_wrong}")

    # Batch verification demo
    print("\n4. Batch verification demo (5 signatures)...")
    n = 5
    batch_keys = [generate_keypair() for _ in range(n)]
    batch_msgs = [f"Batch message {i}".encode() for i in range(n)]
    batch_sigs = [sign(batch_msgs[i], batch_keys[i][0]) for i in range(n)]
    batch_pks = [batch_keys[i][1] for i in range(n)]

    batch_result = batch_verify(batch_sigs, batch_msgs, batch_pks)
    print(f"All {n} signatures valid: {batch_result}")

    print("\n" + "="*60)


if __name__ == "__main__":
    # test_verification()
    # benchmark_verification()
    demo_verification()