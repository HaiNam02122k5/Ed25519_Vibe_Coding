from Ed25519_FieldArithmetic import FieldElement, P

def test_field_arithmetic():
    """Test các phép toán cơ bản"""
    print("Testing Field Arithmetic...")

    # Test zero và one
    zero = FieldElement(value=0)
    one = FieldElement(value=1)
    assert zero.is_zero()
    assert not one.is_zero()
    print("✓ Zero và One")

    # Test addition
    a = FieldElement(value=12345)
    b = FieldElement(value=67890)
    c = a.add(b)
    assert c.to_int() == (12345 + 67890) % P
    print("✓ Addition")

    # Test subtraction
    d = c.sub(b)
    assert d.to_int() == a.to_int()
    print("✓ Subtraction")

    # Test multiplication
    e = a.mul(b)
    expected = (12345 * 67890) % P
    assert e.to_int() == expected
    print("✓ Multiplication")

    # Test squaring
    f = a.square()
    expected = (12345 * 12345) % P
    assert f.to_int() == expected
    print("✓ Squaring")

    # Test inversion
    g = a.invert()
    h = a.mul(g)
    assert h.to_int() == 1
    print("✓ Inversion")

    # Test với số lớn gần p
    big = FieldElement(value=P - 1)
    result = big.add(one)
    assert result.is_zero()
    print("✓ Modulo reduction")

    # Test bytes conversion
    original = FieldElement(value=123456789)
    bytes_data = original.to_bytes()
    recovered = FieldElement.from_bytes(bytes_data)
    assert original == recovered
    print("✓ Bytes conversion")

    # Test sqrt cho perfect square
    x = FieldElement(value=4)
    sqrt_x = x.sqrt()
    assert sqrt_x.square().to_int() == 4
    print("✓ Square root")

    print("\n✅ All Field Arithmetic tests passed!")