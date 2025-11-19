"""
Ed25519 Field Arithmetic Module
Triển khai các phép toán trên trường hữu hạn F_{2^255-19}

Sử dụng biểu diễn radix-2^51 với 5 limbs như mô tả trong paper:
- Mỗi element được biểu diễn là (x0, x1, x2, x3, x4)
- Với x = Σ(i=0 to 4) x_i * 2^(51*i)
- Mỗi limb có tối đa 54 bits trong quá trình tính toán
"""

import gmpy2
from gmpy2 import mpz

# Số nguyên tố của trường: p = 2^255 - 19
P = (1 << 255) - 19

# Constants cho operations
MASK_51 = (1 << 51) - 1  # 0x7ffffffffffff
MASK_52 = (1 << 52) - 1


class FieldElement:
    """
    Biểu diễn một phần tử trong F_{2^255-19}
    Sử dụng 5 limbs, mỗi limb 51 bits (radix-2^51)
    """

    def __init__(self, limbs=None, value=None):
        """
        Khởi tạo FieldElement

        Args:
            limbs: List/tuple của 5 limbs (mỗi limb là int)
            value: Giá trị integer để convert thành limbs
        """
        if limbs is not None:
            if len(limbs) != 5:
                raise ValueError("FieldElement cần đúng 5 limbs")
            self.limbs = list(limbs)
        elif value is not None:
            # Convert integer thành 5 limbs
            value = value % P
            self.limbs = [
                (value >> (51 * 0)) & MASK_51,
                (value >> (51 * 1)) & MASK_51,
                (value >> (51 * 2)) & MASK_51,
                (value >> (51 * 3)) & MASK_51,
                (value >> (51 * 4)) & MASK_51,
            ]
        else:
            # Zero element
            self.limbs = [0, 0, 0, 0, 0]

    def to_int(self):
        """Convert limbs về integer"""
        result = 0
        for i in range(5):
            result += self.limbs[i] << (51 * i)
        return result % P

    def to_bytes(self):
        """Convert sang 32 bytes (little-endian)"""
        value = self.to_int()
        return value.to_bytes(32, byteorder='little')

    @staticmethod
    def from_bytes(data):
        """
        Tạo FieldElement từ 32 bytes (little-endian)

        Args:
            data: bytes object (32 bytes)
        """
        if len(data) != 32:
            raise ValueError("Cần đúng 32 bytes")
        value = int.from_bytes(data, byteorder='little')
        return FieldElement(value=value)

    def __repr__(self):
        return f"FieldElement({self.to_int()})"

    def __eq__(self, other):
        """So sánh bằng"""
        if not isinstance(other, FieldElement):
            return False
        # Reduce cả hai về canonical form trước khi so sánh
        a = self.to_int()
        b = other.to_int()
        return a == b

    def copy(self):
        """Tạo bản sao"""
        return FieldElement(limbs=self.limbs[:])

    def add(self, other):
        """
        Cộng hai FieldElement
        Không cần carry ngay lập tức - để cho multiplication xử lý
        """
        result = FieldElement()
        for i in range(5):
            result.limbs[i] = self.limbs[i] + other.limbs[i]
        return result

    def sub(self, other):
        """
        Trừ hai FieldElement
        Thêm multiple của p trước để tránh số âm (vì dùng unsigned)
        """
        result = FieldElement()
        # Thêm 2*p vào để đảm bảo không âm
        # 2*p ≈ 2^256, chia cho 2^51 cho mỗi limb
        offset = [
            0xfffffffffffda,  # 2*p cho limb 0
            0xffffffffffffe,
            0xffffffffffffe,
            0xffffffffffffe,
            0xffffffffffffe,
        ]
        for i in range(5):
            result.limbs[i] = self.limbs[i] + offset[i] - other.limbs[i]
        return result

    def mul(self, other):
        """
        Nhân hai FieldElement
        Sử dụng schoolbook multiplication với reduction đồng thời

        Theo paper Section 3:
        - 25 multiplications (5x5)
        - Reduction modulo 2^255-19 trong quá trình tính
        - 2^256 ≡ 38 (mod 2^255-19), nên 2^255 ≡ 19
        """
        # Precompute 19 * limbs của other để sử dụng cho reduction
        b = other.limbs
        b19 = [19 * x for x in b]

        a = self.limbs

        # Schoolbook multiplication với reduction
        # Khi tính a_i * b_j với i+j >= 5, nhân b_j với 19 và cộng vào limb (i+j-5)

        r0 = a[0] * b[0] + 19 * (a[1] * b[4] + a[2] * b[3] + a[3] * b[2] + a[4] * b[1])
        r1 = a[0] * b[1] + a[1] * b[0] + 19 * (a[2] * b[4] + a[3] * b[3] + a[4] * b[2])
        r2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + 19 * (a[3] * b[4] + a[4] * b[3])
        r3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + 19 * (a[4] * b[4])
        r4 = a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0]

        result = FieldElement(limbs=[r0, r1, r2, r3, r4])
        result._carry()
        return result

    def square(self):
        """
        Bình phương FieldElement
        Tối ưu hơn mul() vì chỉ cần 15 multiplications thay vì 25
        """
        a = self.limbs
        a19 = [19 * x for x in a]

        # Optimized squaring
        r0 = a[0] * a[0] + 2 * 19 * (a[1] * a[4] + a[2] * a[3])
        r1 = 2 * (a[0] * a[1]) + 2 * 19 * (a[2] * a[4]) + 19 * (a[3] * a[3])
        r2 = 2 * (a[0] * a[2]) + a[1] * a[1] + 2 * 19 * (a[3] * a[4])
        r3 = 2 * (a[0] * a[3] + a[1] * a[2]) + 19 * (a[4] * a[4])
        r4 = 2 * (a[0] * a[4] + a[1] * a[3]) + a[2] * a[2]

        result = FieldElement(limbs=[r0, r1, r2, r3, r4])
        result._carry()
        return result

    def _carry(self):
        """
        Carry reduction: đưa mỗi limb về 51 bits

        Theo paper Section 3:
        1. Shift và mask để tách phần carry
        2. Propagate carry từ limb thấp lên limb cao
        3. Carry từ limb 4 về limb 0 (nhân với 19)
        """
        # First carry pass
        c0 = self.limbs[0] >> 51
        self.limbs[0] &= MASK_51
        self.limbs[1] += c0

        c1 = self.limbs[1] >> 51
        self.limbs[1] &= MASK_51
        self.limbs[2] += c1

        c2 = self.limbs[2] >> 51
        self.limbs[2] &= MASK_51
        self.limbs[3] += c2

        c3 = self.limbs[3] >> 51
        self.limbs[3] &= MASK_51
        self.limbs[4] += c3

        c4 = self.limbs[4] >> 51
        self.limbs[4] &= MASK_51
        self.limbs[0] += c4 * 19  # 2^255 ≡ 19 (mod p)

        # Second carry pass (vì limb[0] có thể > 51 bits sau khi cộng c4*19)
        c0 = self.limbs[0] >> 51
        self.limbs[0] &= MASK_51
        self.limbs[1] += c0

    def neg(self):
        """Phủ định: -x"""
        zero = FieldElement(limbs=[0, 0, 0, 0, 0])
        return zero.sub(self)

    def invert(self):
        """
        Nghịch đảo: x^(-1) mod p
        Sử dụng Fermat's little theorem: x^(-1) = x^(p-2) mod p

        Dùng chuỗi 255 squarings và 11 multiplications như paper mô tả
        """
        # Convert sang integer để dùng pow (hoặc có thể implement square-and-multiply)
        val = self.to_int()
        if val == 0:
            raise ValueError("Không thể invert 0")

        # Tính x^(p-2) mod p
        inv_val = pow(val, P - 2, P)
        return FieldElement(value=inv_val)

    def pow(self, exp):
        """
        Lũy thừa: self^exp mod p
        Sử dụng square-and-multiply
        """
        if exp == 0:
            return FieldElement(value=1)
        if exp == 1:
            return self.copy()
        if exp == 2:
            return self.square()

        # Square-and-multiply
        result = FieldElement(value=1)
        base = self.copy()

        while exp > 0:
            if exp & 1:
                result = result.mul(base)
            base = base.square()
            exp >>= 1

        return result

    def is_zero(self):
        """Kiểm tra có phải zero không"""
        return self.to_int() == 0

    def sqrt(self):
        """
        Tính căn bậc hai modulo p
        Chỉ áp dụng cho quadratic residues

        Vì p ≡ 5 (mod 8), ta dùng công thức:
        sqrt(x) = x^((p+3)/8) hoặc x^((p+3)/8) * sqrt(-1)
        """
        # Tính candidate = self^((p+3)/8)
        exp = (P + 3) // 8
        candidate = self.pow(exp)

        # Check xem candidate^2 == self không
        check = candidate.square()
        if check == self:
            return candidate

        # Nếu không, nhân với sqrt(-1)
        # sqrt(-1) = 2^((p-1)/4) mod p
        sqrt_minus_one = FieldElement(value=2).pow((P - 1) // 4)
        candidate = candidate.mul(sqrt_minus_one)

        # Verify
        check = candidate.square()
        if check == self:
            return candidate

        # Không phải quadratic residue
        raise ValueError("Không tồn tại căn bậc hai")

    def is_negative(self):
        """
        Kiểm tra element có negative không theo encoding convention
        Element là negative nếu bit thấp nhất = 1
        """
        val = self.to_int()
        return val & 1


# Các constants quan trọng
ZERO = FieldElement(value=0)
ONE = FieldElement(value=1)
D = FieldElement(value=(-121665 * pow(121666, P - 2, P)) % P)  # -121665/121666 mod p
SQRT_M1 = FieldElement(value=pow(2, (P - 1) // 4, P))  # sqrt(-1) mod p


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


if __name__ == "__main__":
    test_field_arithmetic()