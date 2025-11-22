import os
import secrets

from Ed25519_EmbeddedSignature import embed_signature, verify_embedded_signature, extract_original_file
from Ed25519_FileSigning import sign_file, verify_file
from Ed25519_KeyGen import generate_keypair, Ed25519PrivateKey, Ed25519PublicKey
from Ed25519_MultiSignature import Signer, create_multisig_document, MultiSignatureDocument
from Ed25519_Sign import sign
from Ed25519_Verify import batch_verify, verify


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


def demo_signing():
    """Demo signing"""
    print("\n" + "="*60)
    print("Ed25519 Signature Generation Demo")
    print("="*60)

    from Ed25519_KeyGen import generate_keypair

    # Generate keypair
    print("\n1. Generating keypair...")
    private_key, public_key = generate_keypair()
    print(f"Public key: {public_key.to_bytes().hex()}")

    # Sign message
    print("\n2. Signing message...")
    message = b"Hello, Ed25519! This is a test message."
    print(f"Message: {message.decode()}")

    signature = sign(message, private_key)
    sig_bytes = signature.to_bytes()

    print(f"\nSignature (64 bytes):")
    print(f"  R: {sig_bytes[:32].hex()}")
    print(f"  S: {sig_bytes[32:].hex()}")

    # Demonstrate determinism
    print("\n3. Demonstrating deterministic signing...")
    sig2 = sign(message, private_key)
    print(f"Same message signed again:")
    print(f"  Signatures match: {signature == sig2}")

    # Different message
    print("\n4. Signing different message...")
    message2 = b"Different message"
    sig3 = sign(message2, private_key)
    print(f"Different message: {message2.decode()}")
    print(f"  Signatures different: {signature != sig3}")

    print("\n" + "="*60)


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


def demo_file_signing():
    """Demo ký file"""
    print("=" * 70)
    print("Ed25519 File Signing Demo")
    print("=" * 70)

    # 1. Generate keypair
    print("\n1. Generating keypair...")
    private_key, public_key = generate_keypair()
    print(f"Public key: {public_key.to_bytes().hex()[:32]}...")

    # 2. Tạo test file
    print("\n2. Creating test file...")
    test_file = "test_document.txt"
    with open(test_file, 'w') as f:
        f.write("This is a confidential document.\n")
        f.write("Signed with Ed25519.\n")
        f.write("Do not modify!\n")
    print(f"Created: {test_file}")

    # 3. Sign file
    print("\n3. Signing file...")
    metadata = {
        "author": "Alice",
        "department": "Security Team",
        "description": "Confidential document"
    }

    file_sig = sign_file(test_file, private_key, metadata=metadata)
    print(f"Signature info:")
    print(f"  Filename: {file_sig.filename}")
    print(f"  Hash: {file_sig.file_hash.hex()[:32]}...")
    print(f"  Timestamp: {file_sig.timestamp}")
    print(f"  Metadata: {file_sig.metadata}")

    # 4. Verify file (chưa thay đổi)
    print("\n4. Verifying original file...")
    result = verify_file(test_file)
    print(f"Valid: {result['valid']}")
    print(f"Message: {result['message']}")

    # 5. Modify file và verify lại
    print("\n5. Modifying file and verifying again...")
    with open(test_file, 'a') as f:
        f.write("TAMPERED CONTENT\n")

    result = verify_file(test_file)
    print(f"Valid: {result['valid']}")
    print(f"Message: {result['message']}")

    # 6. Cleanup
    print("\n6. Cleaning up...")
    if os.path.exists(test_file):
        os.remove(test_file)
    if os.path.exists(test_file + ".sig"):
        os.remove(test_file + ".sig")
    print("Test files removed.")

    print("\n" + "=" * 70)


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


def demo_multisignature():
    """Demo multi-signature workflow"""
    print("=" * 70)
    print("Multi-Signature Demo")
    print("=" * 70)

    # 1. Setup: Tạo 3 signers
    print("\n1. Setting up signers...")

    # Alice (Manager)
    alice_private, alice_public = generate_keypair()
    alice = Signer("Alice", "alice@company.com", alice_public, role="Manager")

    # Bob (Director)
    bob_private, bob_public = generate_keypair()
    bob = Signer("Bob", "bob@company.com", bob_public, role="Director")

    # Charlie (CEO)
    charlie_private, charlie_public = generate_keypair()
    charlie = Signer("Charlie", "charlie@company.com", charlie_public, role="CEO")

    print(f"✓ Alice (Manager): {alice.public_key.to_bytes().hex()[:16]}...")
    print(f"✓ Bob (Director): {bob.public_key.to_bytes().hex()[:16]}...")
    print(f"✓ Charlie (CEO): {charlie.public_key.to_bytes().hex()[:16]}...")

    # 2. Tạo document cần ký
    print("\n2. Creating document...")
    test_file = "contract_multisig.txt"
    with open(test_file, 'w') as f:
        f.write("CONFIDENTIAL CONTRACT\n")
        f.write("=" * 50 + "\n\n")
        f.write("This contract requires approval from:\n")
        f.write("- Manager (Alice)\n")
        f.write("- Director (Bob)\n")
        f.write("- CEO (Charlie)\n\n")
        f.write("Terms: Blah blah blah...\n")

    print(f"Created: {test_file}")

    # 3. Tạo multi-signature document (2-of-3 threshold)
    print("\n3. Creating multi-signature document (2-of-3 threshold)...")

    doc = create_multisig_document(
        file_path=test_file,
        signers_info=[
            {"name": "Alice", "email": "alice@company.com", "public_key": alice_public, "role": "Manager"},
            {"name": "Bob", "email": "bob@company.com", "public_key": bob_public, "role": "Director"},
            {"name": "Charlie", "email": "charlie@company.com", "public_key": charlie_public, "role": "CEO"}
        ],
        threshold=2,  # Cần ít nhất 2/3 signatures
        metadata={
            "title": "Partnership Agreement",
            "department": "Legal",
            "contract_id": "CTR-2024-001"
        }
    )

    print(f"✓ Multi-signature document created")
    print(f"  Threshold: {doc.threshold} of {len(doc.required_signers)}")

    # 4. Alice ký đầu tiên
    print("\n4. Alice signs the document...")
    doc.add_signature(
        private_key=alice_private,
        signer_info=alice,
        comment="Approved by Management"
    )

    status = doc.get_status()
    print(f"  Status: {status['status']}")
    print(f"  Signed: {status['total_signed']}/{status['total_required']}")
    print(f"  Complete: {status['is_complete']}")

    # 5. Bob ký tiếp
    print("\n5. Bob signs the document...")
    doc.add_signature(
        private_key=bob_private,
        signer_info=bob,
        comment="Reviewed and approved"
    )

    status = doc.get_status()
    print(f"  Status: {status['status']}")
    print(f"  Signed: {status['total_signed']}/{status['total_required']}")
    print(f"  Complete: {status['is_complete']}")

    # 6. Save document
    print("\n6. Saving multi-signature document...")
    msig_file = test_file + ".msig"
    doc.save(msig_file)

    # 7. Verify all signatures
    print("\n7. Verifying all signatures...")
    verify_results = doc.verify_all_signatures()
    for email, is_valid in verify_results.items():
        status_icon = "✓" if is_valid else "✗"
        print(f"  {status_icon} {email}: {'VALID' if is_valid else 'INVALID'}")

    # 8. Display signature chain
    print("\n8. Signature chain (chronological order):")
    chain = doc.get_signature_chain()
    for i, record in enumerate(chain, 1):
        print(f"  {i}. {record.signer.name} ({record.signer.role})")
        print(f"     Email: {record.signer.email}")
        print(f"     Time: {record.timestamp}")
        print(f"     Comment: {record.comment}")
        print()

    # 9. Charlie có thể ký thêm (optional vì đã đủ threshold)
    print("9. Charlie can optionally sign (already have 2/3)...")
    choice = input("   Should Charlie sign too? (y/n): ").strip().lower()

    if choice == 'y':
        doc.add_signature(
            private_key=charlie_private,
            signer_info=charlie,
            comment="Final approval from CEO"
        )
        status = doc.get_status()
        print(f"  Status: {status['status']}")
        print(f"  Signed: {status['total_signed']}/{status['total_required']}")

        # Re-save
        doc.save(msig_file)

    # 10. Load và verify từ file
    print("\n10. Loading and verifying from saved file...")
    loaded_doc = MultiSignatureDocument.load(msig_file, test_file)

    status = loaded_doc.get_status()
    print(f"  Status: {status['status']}")
    print(f"  Complete: {status['is_complete']}")
    print(f"  Valid signatures: {status['valid_signatures']}/{status['threshold']} (threshold)")

    # 11. Cleanup
    print("\n11. Cleaning up...")
    if os.path.exists(test_file):
        os.remove(test_file)
    if os.path.exists(msig_file):
        os.remove(msig_file)
    print("Test files removed.")

    print("\n" + "=" * 70)


def demo_threshold_scenarios():
    """Demo các scenarios threshold khác nhau"""
    print("=" * 70)
    print("Threshold Scenarios Demo")
    print("=" * 70)

    scenarios = [
        {
            "name": "All Must Sign (3-of-3)",
            "description": "Critical decisions requiring unanimous approval",
            "threshold": 3,
            "example": "Board of Directors unanimous vote"
        },
        {
            "name": "Majority (2-of-3)",
            "description": "Most decisions requiring majority",
            "threshold": 2,
            "example": "Standard contract approval"
        },
        {
            "name": "Any One (1-of-3)",
            "description": "Any authorized person can approve",
            "threshold": 1,
            "example": "Expense approval under $1000"
        },
        {
            "name": "Quorum (3-of-5)",
            "description": "Need 60% approval",
            "threshold": 3,
            "example": "Committee decisions"
        }
    ]

    print("\nCommon Multi-Signature Scenarios:\n")

    for i, scenario in enumerate(scenarios, 1):
        print(f"{i}. {scenario['name']}")
        print(f"   Description: {scenario['description']}")
        print(f"   Example: {scenario['example']}")
        print()

    print("=" * 70)


