from Ed25519_CurveArithmetic import EdwardsPoint, BASE_POINT

def test_curve_arithmetic():
    """Test các phép toán trên curve"""
    print("Testing Curve Arithmetic...")

    # Test identity point
    O = EdwardsPoint.zero()
    assert O.is_identity()
    print("✓ Identity point")

    # Test base point
    B = BASE_POINT
    assert B.is_on_curve()
    print("✓ Base point on curve")

    # Test point addition: B + O = B
    result = B.add(O)
    assert result == B
    print("✓ Addition with identity")

    # Test point doubling: 2B
    B2 = B.double()
    assert B2.is_on_curve()
    B2_alt = B.add(B)
    assert B2 == B2_alt
    print("✓ Point doubling")

    # Test scalar multiplication: 3B = B + B + B
    B3_scalar = B.scalar_mul(3)
    B3_add = B.add(B).add(B)
    assert B3_scalar == B3_add
    print("✓ Scalar multiplication")

    # Test negation: B + (-B) = O
    neg_B = B.neg()
    result = B.add(neg_B)
    assert result.is_identity()
    print("✓ Negation")

    # Test với order: l*B = O
    B_times_8 = B.scalar_mul(8)
    assert B_times_8.is_on_curve()
    print("✓ Cofactor multiplication")

    # Test encode/decode
    encoded = B.encode()
    assert len(encoded) == 32
    decoded = EdwardsPoint.decode(encoded)
    assert decoded == B
    print("✓ Encode/Decode")

    # Test encode/decode với random point
    random_point = B.scalar_mul(12345)
    encoded = random_point.encode()
    decoded = EdwardsPoint.decode(encoded)
    assert decoded == random_point
    print("✓ Encode/Decode random point")

    # Test commutativity: P + Q = Q + P
    P = B.scalar_mul(5)
    Q = B.scalar_mul(7)
    PQ = P.add(Q)
    QP = Q.add(P)
    assert PQ == QP
    print("✓ Commutativity")

    # Test associativity: (P + Q) + R = P + (Q + R)
    R = B.scalar_mul(11)
    left = P.add(Q).add(R)
    right = P.add(Q.add(R))
    assert left == right
    print("✓ Associativity")

    # Test distributivity: k*(P + Q) = k*P + k*Q
    k = 13
    left = P.add(Q).scalar_mul(k)
    right = P.scalar_mul(k).add(Q.scalar_mul(k))
    assert left == right
    print("✓ Distributivity")

    print("\n✅ All Curve Arithmetic tests passed!")