# Quy trình tổng quát Ed25519 Digital Signature System

## 📋 Mục lục
1. [Tổng quan hệ thống](#1-tổng-quan-hệ-thống)
2. [Setup ban đầu](#2-setup-ban-đầu)
3. [Quy trình ký (Signing)](#3-quy-trình-ký-signing)
4. [Quy trình xác thực (Verification)](#4-quy-trình-xác-thực-verification)
5. [Quy trình ký file](#5-quy-trình-ký-file)
6. [Sơ đồ luồng hoàn chỉnh](#6-sơ-đồ-luồng-hoàn-chỉnh)

---

## 1. Tổng quan hệ thống

### 🎯 Mục đích
Ed25519 là hệ thống chữ ký số (digital signature) dựa trên elliptic curve cryptography, đảm bảo:
- **Tính toàn vẹn (Integrity)**: Phát hiện file/message bị sửa đổi
- **Tính xác thực (Authentication)**: Xác nhận người ký
- **Tính không thể chối bỏ (Non-repudiation)**: Người ký không thể phủ nhận

### 🔑 Thành phần chính
```
┌─────────────────────────────────────────────────────────┐
│                    Ed25519 System                        │
├─────────────────────────────────────────────────────────┤
│                                                           │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────┐ │
│  │ Private Key │───▶│   Signing    │───▶│ Signature  │ │
│  │  (32 bytes) │    │   Process    │    │ (64 bytes) │ │
│  └─────────────┘    └──────────────┘    └────────────┘ │
│                                                           │
│  ┌─────────────┐    ┌──────────────┐    ┌────────────┐ │
│  │ Public Key  │───▶│ Verification │───▶│   Valid?   │ │
│  │  (32 bytes) │    │   Process    │    │  Yes/No    │ │
│  └─────────────┘    └──────────────┘    └────────────┘ │
│                                                           │
└─────────────────────────────────────────────────────────┘
```

---

## 2. Setup ban đầu

### 📦 Cài đặt dependencies
```bash
pip install gmpy2 numpy
```

### 🔧 Cấu trúc project
```
Ed25519_Project/
├── Ed25519_FieldArithmetic.py      # Field F_{2^255-19}
├── Ed25519_CurveArithmetic.py      # Twisted Edwards curve
├── Ed25519_KeyGen.py               # Key generation
├── Ed25519_Sign.py                 # Signature generation
├── Ed25519_Verify.py               # Signature verification
├── Ed25519_FileSigning.py          # File signing utilities
└── keys/                           # Thư mục lưu keys
    ├── private_key.bin
    └── public_key.bin
```

### 🎲 Tạo keypair
```python
from Ed25519_KeyGen import generate_keypair

# Generate new keypair
private_key, public_key = generate_keypair()

# Save keys
with open('private_key.bin', 'wb') as f:
    f.write(private_key.to_bytes())  # 32 bytes

with open('public_key.bin', 'wb') as f:
    f.write(public_key.to_bytes())   # 32 bytes
```

**⚠️ QUAN TRỌNG:**
- **Private key**: Giữ bí mật tuyệt đối, không chia sẻ
- **Public key**: Có thể công khai, chia sẻ với mọi người

---

## 3. Quy trình ký (Signing)

### 📝 Sơ đồ tổng quan
```
┌──────────────┐
│   Message    │
│  (bất kỳ)    │
└──────┬───────┘
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│              SIGNING PROCESS                              │
├──────────────────────────────────────────────────────────┤
│                                                            │
│  Step 1: Derive key material                              │
│  ┌────────────┐                                           │
│  │Private Key │                                           │
│  │ (seed 32B) │                                           │
│  └─────┬──────┘                                           │
│        │                                                   │
│        ▼                                                   │
│  ┌──────────────────────┐                                │
│  │   SHA-512(seed)      │                                │
│  │   Output: 64 bytes   │                                │
│  └──────┬───────────────┘                                │
│         │                                                  │
│    ┌────┴────┐                                            │
│    ▼         ▼                                            │
│  [0:32]   [32:64]                                         │
│    │         │                                            │
│  Clamp    Prefix                                          │
│    │         │                                            │
│    ▼         │                                            │
│  Scalar a   │                                             │
│             │                                             │
│  ┌──────────▼────────────┐                               │
│  │ Step 2: Compute r     │                               │
│  │ r = H(prefix || M)    │                               │
│  │   mod ℓ               │                               │
│  └──────────┬────────────┘                               │
│             │                                             │
│             ▼                                             │
│  ┌──────────────────────┐                                │
│  │ Step 3: Compute R    │                                │
│  │ R = r × B            │                                │
│  │ (scalar mult)        │                                │
│  └──────────┬───────────┘                                │
│             │                                             │
│             ▼                                             │
│  ┌─────────────────────────┐                             │
│  │ Step 4: Compute k       │                             │
│  │ k = H(R || A || M)      │                             │
│  │   mod ℓ                 │                             │
│  └──────────┬──────────────┘                             │
│             │                                             │
│             ▼                                             │
│  ┌─────────────────────────┐                             │
│  │ Step 5: Compute S       │                             │
│  │ S = (r + k×a) mod ℓ     │                             │
│  └──────────┬──────────────┘                             │
│             │                                             │
│             ▼                                             │
│  ┌─────────────────────────┐                             │
│  │ Output: (R, S)          │                             │
│  │ Signature = R || S      │                             │
│  │ Size: 64 bytes          │                             │
│  └─────────────────────────┘                             │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### 🔢 Chi tiết từng bước

#### **Step 1: Key Derivation**
```
Input: Private key seed (32 bytes)

Process:
  h = SHA-512(seed) → 64 bytes
  
  h[0:32]  → Scalar a (sau khi clamp)
  h[32:64] → Prefix (cho signing)

Clamping:
  h[0]  &= 248  (clear bits 0,1,2)
  h[31] &= 127  (clear bit 255)
  h[31] |= 64   (set bit 254)
  
  → Scalar a ∈ [2^254, 2^255) và chia hết cho 8

Public Key:
  A = a × B (B là base point)
```

#### **Step 2: Compute nonce r**
```
Input: prefix (32 bytes), message M

Process:
  r_hash = SHA-512(prefix || M) → 64 bytes
  r = r_hash mod ℓ
  
  ℓ = 2^252 + 27742317777372353535851937790883648493
  
Note: r là deterministic (không cần random per-message)
```

#### **Step 3: Compute R**
```
Input: r (scalar), B (base point)

Process:
  R = r × B
  
Implementation:
  - Sử dụng precomputed table
  - Radix-16 hoặc window method
  - Fast fixed-base scalar multiplication
  
Output: R (point trên curve)
```

#### **Step 4: Compute challenge k**
```
Input: R, A (public key), M (message)

Process:
  R_bytes = encode(R)    (32 bytes)
  A_bytes = encode(A)    (32 bytes)
  
  k_hash = SHA-512(R_bytes || A_bytes || M) → 64 bytes
  k = k_hash mod ℓ
  
Note: k phụ thuộc vào R, A, và M
```

#### **Step 5: Compute response S**
```
Input: r, k, a (scalar)

Process:
  S = (r + k × a) mod ℓ
  
Output: S (scalar, 32 bytes little-endian)
```

#### **Final Signature**
```
Signature = R || S

Format:
  Bytes 0-31:  R (compressed point)
  Bytes 32-63: S (scalar)
  
Total: 64 bytes
```

### 💻 Code example
```python
from Ed25519_Sign import sign

# Sign a message
message = b"Hello, World!"
signature = sign(message, private_key)

# Get signature bytes
sig_bytes = signature.to_bytes()  # 64 bytes
print(f"Signature: {sig_bytes.hex()}")
```

---

## 4. Quy trình xác thực (Verification)

### 🔍 Sơ đồ tổng quan
```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│  Signature   │  │   Message    │  │  Public Key  │
│   (64 bytes) │  │  (bất kỳ)    │  │  (32 bytes)  │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │
       └─────────────────┴─────────────────┘
                         │
                         ▼
┌────────────────────────────────────────────────────────┐
│           VERIFICATION PROCESS                          │
├────────────────────────────────────────────────────────┤
│                                                          │
│  Step 1: Parse signature                                │
│  ┌────────────────────┐                                │
│  │  Signature bytes   │                                │
│  │    (64 bytes)      │                                │
│  └─────┬──────────────┘                                │
│        │                                                │
│    ┌───┴───┐                                            │
│    ▼       ▼                                            │
│  R (32B)  S (32B)                                       │
│    │       │                                            │
│ Decode   Parse                                          │
│  point   scalar                                         │
│                                                          │
│  Step 2: Check S < ℓ                                   │
│  ┌────────────────────┐                                │
│  │  If S >= ℓ         │                                │
│  │  → REJECT          │                                │
│  └────────────────────┘                                │
│                                                          │
│  Step 3: Compute k                                      │
│  ┌────────────────────────┐                            │
│  │  k = H(R || A || M)    │                            │
│  │    mod ℓ               │                            │
│  └────────┬───────────────┘                            │
│           │                                             │
│           ▼                                             │
│  Step 4: Verify equation                                │
│  ┌─────────────────────────────────┐                   │
│  │  Compute:                       │                   │
│  │    Left  = 8×S×B                │                   │
│  │    Right = 8×R + 8×(k×A)        │                   │
│  │                                 │                   │
│  │  Check: Left == Right?          │                   │
│  └──────────┬──────────────────────┘                   │
│             │                                           │
│        ┌────┴────┐                                      │
│        ▼         ▼                                      │
│      Equal   Not Equal                                  │
│        │         │                                      │
│        ▼         ▼                                      │
│     VALID    INVALID                                    │
│                                                          │
└────────────────────────────────────────────────────────┘
```

### 🔢 Chi tiết từng bước

#### **Step 1: Parse Signature**
```
Input: Signature (64 bytes)

Process:
  R_bytes = signature[0:32]
  S_bytes = signature[32:64]
  
  R = decode_point(R_bytes)
    → Giải nén compressed point
    → Tính x từ y và curve equation
  
  S = int.from_bytes(S_bytes, 'little')
    → Convert little-endian sang integer
```

#### **Step 2: Validate S**
```
Check: S < ℓ

If S >= ℓ:
  return INVALID
  
Reason: S phải nằm trong group order
```

#### **Step 3: Compute Challenge**
```
Input: R, A, M

Process:
  R_bytes = encode(R)
  A_bytes = encode(A)
  
  k_hash = SHA-512(R_bytes || A_bytes || M)
  k = k_hash mod ℓ
  
Note: Phải giống với k trong signing
```

#### **Step 4: Verify Equation**
```
Equation to verify:
  8×S×B = 8×R + 8×(k×A)

Equivalent forms:
  S×B = R + k×A  (vì cofactor = 8)
  
Implementation:
  1. Compute left  = scalar_mul(8×S, B)
  2. Compute right = 8×R + scalar_mul(8×k, A)
  3. Compare points: left == right?

Optimization:
  - Sử dụng double-scalar multiplication
  - Shamir's trick cho k×A + S×B
```

### 💻 Code example
```python
from Ed25519_Verify import verify

# Verify a signature
is_valid = verify(signature, message, public_key)

if is_valid:
    print("✓ Signature is VALID")
    print("  - Message không bị sửa đổi")
    print("  - Được ký bởi owner của public key")
else:
    print("✗ Signature is INVALID")
    print("  - Message có thể bị thay đổi")
    print("  - Hoặc signature không đúng")
```

---

## 5. Quy trình ký file

### 📄 Sơ đồ tổng quan
```
┌────────────────────────────────────────────────────────┐
│                  FILE SIGNING PROCESS                   │
├────────────────────────────────────────────────────────┤
│                                                          │
│  ┌─────────────┐                                        │
│  │   File      │  (PDF, DOCX, Image, etc.)             │
│  │  document   │                                        │
│  │   .pdf      │                                        │
│  └──────┬──────┘                                        │
│         │                                                │
│         ▼                                                │
│  ┌──────────────────┐                                  │
│  │ Compute Hash     │                                  │
│  │ SHA-256(file)    │                                  │
│  └──────┬───────────┘                                  │
│         │                                                │
│         ▼                                                │
│  ┌──────────────────┐                                  │
│  │  File Hash       │                                  │
│  │  (32 bytes)      │                                  │
│  └──────┬───────────┘                                  │
│         │                                                │
│         ▼                                                │
│  ┌──────────────────────────┐                          │
│  │  Sign Hash               │                          │
│  │  signature = sign(hash)  │                          │
│  └──────┬───────────────────┘                          │
│         │                                                │
│         ▼                                                │
│  ┌──────────────────────────────────┐                  │
│  │  Create Signature File           │                  │
│  │  {                               │                  │
│  │    "filename": "document.pdf",   │                  │
│  │    "file_hash": "a3f5...",       │                  │
│  │    "signature": "e556...",       │                  │
│  │    "public_key": "d75a...",      │                  │
│  │    "timestamp": "2024-01-15",    │                  │
│  │    "metadata": {...}             │                  │
│  │  }                               │                  │
│  └──────┬───────────────────────────┘                  │
│         │                                                │
│         ▼                                                │
│  ┌──────────────────┐                                  │
│  │  Save to file    │                                  │
│  │  document.pdf    │                                  │
│  │  document.pdf    │                                  │
│  │         .sig     │                                  │
│  └──────────────────┘                                  │
│                                                          │
└────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────┐
│               FILE VERIFICATION PROCESS                 │
├────────────────────────────────────────────────────────┤
│                                                          │
│  ┌──────────────┐  ┌──────────────┐                   │
│  │  File to     │  │  Signature   │                   │
│  │  verify      │  │  file .sig   │                   │
│  │document.pdf  │  │              │                   │
│  └──────┬───────┘  └──────┬───────┘                   │
│         │                 │                             │
│         │                 ▼                             │
│         │      ┌────────────────────┐                  │
│         │      │ Load signature     │                  │
│         │      │ Parse JSON         │                  │
│         │      └──────┬─────────────┘                  │
│         │             │                                 │
│         ▼             ▼                                 │
│  ┌──────────────────────────┐                          │
│  │ Compute current hash     │                          │
│  │ current_hash = SHA-256() │                          │
│  └──────┬───────────────────┘                          │
│         │                                                │
│         ▼                                                │
│  ┌──────────────────────────┐                          │
│  │ Compare hashes           │                          │
│  │ current == stored?       │                          │
│  └──────┬───────────────────┘                          │
│         │                                                │
│    ┌────┴────┐                                          │
│    ▼         ▼                                          │
│  Equal   Not Equal                                      │
│    │         │                                          │
│    │         └──▶ MODIFIED                              │
│    │                                                     │
│    ▼                                                     │
│  ┌──────────────────────────┐                          │
│  │ Verify signature         │                          │
│  │ verify(sig, hash, pk)    │                          │
│  └──────┬───────────────────┘                          │
│         │                                                │
│    ┌────┴────┐                                          │
│    ▼         ▼                                          │
│  Valid   Invalid                                        │
│    │         │                                          │
│    ▼         ▼                                          │
│  ✓ OK    ✗ TAMPERED                                    │
│                                                          │
└────────────────────────────────────────────────────────┘
```

### 💻 Code example
```python
from Ed25519_FileSigning import sign_file, verify_file

# === SIGNING ===
# Sign a PDF document
sign_file(
    file_path="contract.pdf",
    private_key=private_key,
    metadata={
        "author": "Alice",
        "type": "Legal Contract",
        "date": "2024-01-15"
    }
)
# Output: contract.pdf.sig

# === VERIFICATION ===
# Verify the PDF
result = verify_file("contract.pdf")

if result['valid']:
    print("✓ File is authentic and unmodified")
    print(f"Signed by: {result['signature_info']['metadata']['author']}")
    print(f"Signed at: {result['signature_info']['timestamp']}")
else:
    print("✗ File has been tampered with!")
    print(f"Reason: {result['message']}")
```

---

## 6. Sơ đồ luồng hoàn chỉnh

### 🎬 End-to-End Workflow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    COMPLETE WORKFLOW                                 │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────┐
│  Alice      │  (Người ký)
└──────┬──────┘
       │
       │ 1. Generate keypair
       ▼
┌────────────────────┐
│ Private Key (32B)  │  ← Giữ bí mật
│ Public Key (32B)   │  ← Công khai
└──────┬─────────────┘
       │
       │ 2. Share public key
       ▼
┌────────────────────┐
│  Public Registry   │  (Website, keyserver, blockchain)
│  Alice: d75a...    │
└────────────────────┘
       │
       │ 3. Sign document
       ▼
┌────────────────────┐
│  document.pdf      │
│  document.pdf.sig  │  ← Gửi cả 2 files
└──────┬─────────────┘
       │
       │ 4. Send to Bob
       ▼
┌─────────────┐
│    Bob      │  (Người nhận)
└──────┬──────┘
       │
       │ 5. Receive files
       ▼
┌────────────────────┐
│  document.pdf      │
│  document.pdf.sig  │
└──────┬─────────────┘
       │
       │ 6. Get Alice's public key
       ▼
┌────────────────────┐
│  Public Registry   │
│  Alice: d75a...    │
└──────┬─────────────┘
       │
       │ 7. Verify signature
       ▼
┌──────────────────────────────┐
│  Verification Result:         │
│  ✓ Valid                      │
│  ✓ From Alice                 │
│  ✓ Not modified               │
│  ✓ Signed: 2024-01-15         │
└───────────────────────────────┘
```

### 🔄 Các scenario khác nhau

#### **Scenario 1: Valid Signature**
```
Alice signs → Bob receives → Verify: ✓ VALID
→ Bob tin tài liệu từ Alice và chưa bị sửa
```

#### **Scenario 2: Modified Document**
```
Alice signs → Hacker modifies PDF → Bob receives → Verify: ✗ INVALID
→ Hash không khớp → Bob biết file bị sửa
```

#### **Scenario 3: Forged Signature**
```
Hacker creates fake signature → Bob receives → Verify: ✗ INVALID
→ Signature equation không đúng → Bob biết signature giả
```

#### **Scenario 4: Wrong Public Key**
```
Alice signs → Bob dùng public key của Eve → Verify: ✗ INVALID
→ Bob biết signature không phải của Alice
```

---

## 📊 Bảng so sánh các thành phần

| Thành phần | Kích thước | Bí mật? | Mục đích |
|------------|-----------|---------|----------|
| Private Key Seed | 32 bytes | ✓ Bí mật | Ký messages |
| Private Key Scalar | 32 bytes | ✓ Bí mật | Scalar a (sau clamp) |
| Private Key Prefix | 32 bytes | ✓ Bí mật | Generate nonce r |
| Public Key | 32 bytes | ✗ Công khai | Verify signatures |
| Signature R | 32 bytes | ✗ Công khai | Part 1 của signature |
| Signature S | 32 bytes | ✗ Công khai | Part 2 của signature |
| Message Hash | 32 bytes | ✗ Công khai | SHA-256 của message |

---

## 🔐 Security Properties

### ✅ Đảm bảo
1. **Correctness**: Valid signature luôn verify thành công
2. **Unforgeability**: Không thể tạo valid signature mà không có private key
3. **Non-malleability**: Không thể modify signature thành signature khác
4. **Deterministic**: Cùng message + key → cùng signature
5. **Collision-resistant**: Hash collision không break scheme

### ⚠️ Assumptions
1. **SHA-512 an toàn**: Cryptographically secure hash
2. **ECDLP khó**: Không thể tính discrete log trên curve
3. **Random nonce**: Private key seed thực sự random
4. **Key secrecy**: Private key được bảo vệ tốt

---

## 🎓 Thuật ngữ quan trọng

| Thuật ngữ | Giải thích |
|-----------|-----------|
| **Scalar** | Số nguyên dùng để nhân với point trên curve |
| **Point** | Điểm (x, y) trên elliptic curve |
| **Base Point B** | Generator point của curve group |
| **Order ℓ** | Số lượng points trong subgroup generated bởi B |
| **Cofactor** | Tỷ lệ giữa curve order và subgroup order (= 8) |
| **Clamping** | Điều chỉnh scalar để đảm bảo security properties |
| **Nonce r** | Random-looking value dùng cho mỗi signature |
| **Challenge k** | Hash-derived scalar trong verification |

---

## 📚 Tài liệu tham khảo

1. **RFC 8032**: Edwards-Curve Digital Signature Algorithm (EdDSA)
2. **Original Paper**: "High-speed high-security signatures" (Bernstein et al., 2011)
3. **Curve25519**: "Curve25519: new Diffie-Hellman speed records" (Bernstein, 2006)

---

## ❓ FAQ

### Q: Tại sao cần clamp scalar?
**A**: Clamping đảm bảo scalar có properties tốt:
- Divisible by 8 (cofactor)
- In range [2^254, 2^255)
- Tránh weak scalars
- Constant-time operations

### Q: Tại sao signature deterministic?
**A**: 
- ✅ Không cần random per-message
- ✅ Tránh nonce reuse attacks
- ✅ Reproducible signatures
- ✅ Simpler implementation

### Q: Có thể dùng chung keypair cho nhiều purposes?
**A**: Không nên. Tạo keypair riêng cho:
- Signing documents
- Signing code
- Signing emails
- etc.

### Q: Làm sao backup private key an toàn?
**A**:
- Paper wallet (print và cất kỹ)
- Hardware security module (HSM)
- Encrypted backup với strong password
- Split key (Shamir's Secret Sharing)

---

**Tổng kết**: Ed25519 là hệ thống chữ ký số hiện đại, nhanh, an toàn và dễ implement. Với 32-byte keys và 64-byte signatures, nó hiệu quả hơn nhiều so với RSA cùng security level.