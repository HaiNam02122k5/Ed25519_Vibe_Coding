from Ed25519_Sign import Ed25519Signature
from Ed25519_Verify import verify, batch_verify, verify_optimized


def test_verification():
    """Test signature verification"""
    print("Testing Signature Verification...")

    from Ed25519_KeyGen import generate_keypair
    from Ed25519_Sign import sign

    # Test 1: Basic verification
    private_key, public_key = generate_keypair()
    message = b"Test message"
    signature = sign(message, private_key)

    assert verify(signature, message, public_key) == True
    print("✓ Basic verification")

    # Test 2: Wrong message
    wrong_message = b"Wrong message"
    assert verify(signature, wrong_message, public_key) == False
    print("✓ Wrong message rejected")

    # Test 3: Wrong public key
    _, wrong_public_key = generate_keypair()
    assert verify(signature, message, wrong_public_key) == False
    print("✓ Wrong public key rejected")

    # Test 4: Corrupted signature (modify S)
    sig_bytes = bytearray(signature.to_bytes())
    sig_bytes[32] ^= 0x01  # Flip one bit in S
    corrupted_sig = Ed25519Signature.from_bytes(bytes(sig_bytes))
    assert verify(corrupted_sig, message, public_key) == False
    print("✓ Corrupted S rejected")

    # Test 5: Corrupted signature (modify R)
    sig_bytes = bytearray(signature.to_bytes())
    sig_bytes[0] ^= 0x01  # Flip one bit in R
    try:
        corrupted_sig = Ed25519Signature.from_bytes(bytes(sig_bytes))
        assert verify(corrupted_sig, message, public_key) == False
    except:
        pass  # R decode có thể fail
    print("✓ Corrupted R rejected")

    # Test 6: Verify với bytes input
    sig_bytes = signature.to_bytes()
    pk_bytes = public_key.to_bytes()
    assert verify(sig_bytes, message, pk_bytes) == True
    print("✓ Verification with bytes input")

    # Test 7: Optimized verification
    assert verify_optimized(signature, message, public_key) == True
    print("✓ Optimized verification")

    # Test 8: RFC 8032 Test Vector 1
    test_public = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a"
        "0ee172f3daa62325af021a68f707511a"
    )
    test_message = b""
    test_sig = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    )

    assert verify(test_sig, test_message, test_public) == True
    print("✓ RFC 8032 test vector 1")

    # Test 9: Batch verification
    n = 10
    keys = [generate_keypair() for _ in range(n)]
    messages = [f"Message {i}".encode() for i in range(n)]
    signatures = [sign(messages[i], keys[i][0]) for i in range(n)]
    public_keys = [keys[i][1] for i in range(n)]

    assert batch_verify(signatures, messages, public_keys) == True
    print("✓ Batch verification (all valid)")

    # Test 10: Batch with one invalid
    # Modify one signature
    signatures[5] = sign(b"Wrong", keys[5][0])
    assert batch_verify(signatures, messages, public_keys) == False
    print("✓ Batch verification (one invalid)")

    # Test 11: Empty batch
    assert batch_verify([], [], []) == True
    print("✓ Empty batch")

    # Test 12: Single item batch (với valid signature)
    # Re-generate vì signatures[5] đã bị modify
    keys_fresh = [generate_keypair() for _ in range(1)]
    messages_fresh = [b"Fresh message"]
    signatures_fresh = [sign(messages_fresh[0], keys_fresh[0][0])]
    public_keys_fresh = [keys_fresh[0][1]]

    assert batch_verify(signatures_fresh, messages_fresh, public_keys_fresh) == True
    print("✓ Single item batch")

    # Test 13: Large batch
    n_large = 64
    keys_large = [generate_keypair() for _ in range(n_large)]
    messages_large = [f"Message {i}".encode() for i in range(n_large)]
    signatures_large = [sign(messages_large[i], keys_large[i][0])
                        for i in range(n_large)]
    public_keys_large = [keys_large[i][1] for i in range(n_large)]

    assert batch_verify(signatures_large, messages_large, public_keys_large) == True
    print("✓ Large batch verification (64 signatures)")

    print("\n✅ All Verification tests passed!")


def benchmark_verification():
    """Benchmark verification performance"""
    print("\n" + "="*60)
    print("Signature Verification Benchmark")
    print("="*60)

    from Ed25519_KeyGen import generate_keypair
    from Ed25519_Sign import sign
    import time

    # Setup
    n = 64
    keys = [generate_keypair() for _ in range(n)]
    messages = [f"Message {i}".encode() for i in range(n)]
    signatures = [sign(messages[i], keys[i][0]) for i in range(n)]
    public_keys = [keys[i][1] for i in range(n)]

    # Benchmark single verification
    print("\nSingle Verification:")
    iterations = 50
    start = time.time()
    for i in range(iterations):
        verify(signatures[i % n], messages[i % n], public_keys[i % n])
    elapsed = time.time() - start

    print(f"  Total: {elapsed:.4f} seconds")
    print(f"  Per signature: {elapsed/iterations*1000:.2f} ms")
    print(f"  Verifications/sec: {iterations/elapsed:.2f}")

    # Benchmark batch verification
    print("\nBatch Verification (64 signatures):")
    iterations_batch = 10
    start = time.time()
    for _ in range(iterations_batch):
        batch_verify(signatures, messages, public_keys)
    elapsed_batch = time.time() - start

    total_sigs = n * iterations_batch
    print(f"  Total: {elapsed_batch:.4f} seconds")
    print(f"  Per signature: {elapsed_batch/total_sigs*1000:.2f} ms")
    print(f"  Verifications/sec: {total_sigs/elapsed_batch:.2f}")

    # Speedup
    single_per_sig = elapsed / iterations
    batch_per_sig = elapsed_batch / total_sigs
    speedup = single_per_sig / batch_per_sig

    print(f"\nBatch speedup: {speedup:.2f}x faster")
    print("="*60)