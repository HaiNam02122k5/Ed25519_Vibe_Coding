from Ed25519_KeyGen import generate_keypair, Ed25519PublicKey, Ed25519PrivateKey, EdwardsPoint
from Ed25519_CurveArithmetic import BASE_POINT

def test_key_generation():
    """Test key generation"""
    print("Testing Key Generation...")

    # Test 1: Generate random keypair
    private_key, public_key = generate_keypair()
    assert len(private_key.to_bytes()) == 32
    assert len(public_key.to_bytes()) == 32
    print("✓ Generate random keypair")

    # Test 2: Deterministic key derivation
    # Nếu seed giống nhau → keys giống nhau
    seed1 = b'\x00' * 32
    pk1 = Ed25519PrivateKey(seed=seed1)
    pk2 = Ed25519PrivateKey(seed=seed1)
    assert pk1.get_public_key() == pk2.get_public_key()
    print("✓ Deterministic derivation")

    # Test 3: Different seeds → different keys
    seed2 = b'\x01' * 32
    pk3 = Ed25519PrivateKey(seed=seed2)
    assert pk1.get_public_key() != pk3.get_public_key()
    print("✓ Different seeds produce different keys")

    # Test 4: Scalar clamping
    # Kiểm tra bits được set/cleared đúng
    private_key = Ed25519PrivateKey()
    scalar_bytes = private_key.scalar_bytes

    # Bit 0,1,2 phải = 0 (divisible by 8)
    assert (scalar_bytes[0] & 0b00000111) == 0

    # Bit 254 phải = 1
    assert (scalar_bytes[31] & 0b01000000) != 0

    # Bit 255 phải = 0
    assert (scalar_bytes[31] & 0b10000000) == 0
    print("✓ Scalar clamping correct")

    # Test 5: Public key serialization
    _, public_key = generate_keypair()
    serialized = public_key.to_bytes()
    deserialized = Ed25519PublicKey.from_bytes(serialized)
    assert public_key == deserialized
    print("✓ Public key serialization")

    # Test 6: Private key serialization
    private_key, _ = generate_keypair()
    serialized = private_key.to_bytes()
    deserialized = Ed25519PrivateKey.from_bytes(serialized)
    assert private_key.get_public_key() == deserialized.get_public_key()
    print("✓ Private key serialization")

    # Test 7: Public key on curve
    _, public_key = generate_keypair()
    assert public_key.point.is_on_curve()
    print("✓ Public key on curve")

    # Test 8: Public key = scalar * BASE_POINT
    private_key, public_key = generate_keypair()
    computed = BASE_POINT.scalar_mul(private_key.scalar)
    assert computed == public_key.point
    print("✓ Public key = scalar * BASE_POINT")

    # Test 9: Scalar trong range hợp lệ
    private_key = Ed25519PrivateKey()
    # Scalar phải >= 2^254
    assert private_key.scalar >= (1 << 254)
    # Scalar phải < 2^255
    assert private_key.scalar < (1 << 255)
    # Scalar phải chia hết cho 8
    assert private_key.scalar % 8 == 0
    print("✓ Scalar in valid range")

    # Test 10: Test với known test vector (nếu có)
    # RFC 8032 test vector 1
    test_seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc4"
        "4449c5697b326919703bac031cae7f60"
    )
    test_private = Ed25519PrivateKey(seed=test_seed)
    test_public = test_private.get_public_key()

    expected_public = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a"
        "0ee172f3daa62325af021a68f707511a"
    )

    assert test_public.to_bytes() == expected_public
    print("✓ RFC 8032 test vector 1")

    # Test vector 2
    test_seed2 = bytes.fromhex(
        "4ccd089b28ff96da9db6c346ec114e0f"
        "5b8a319f35aba624da8cf6ed4fb8a6fb"
    )
    test_private2 = Ed25519PrivateKey(seed=test_seed2)
    test_public2 = test_private2.get_public_key()

    expected_public2 = bytes.fromhex(
        "3d4017c3e843895a92b70aa74d1b7ebc"
        "9c982ccf2ec4968cc0cd55f12af4660c"
    )

    assert test_public2.to_bytes() == expected_public2
    print("✓ RFC 8032 test vector 2")

    print("\n✅ All Key Generation tests passed!")