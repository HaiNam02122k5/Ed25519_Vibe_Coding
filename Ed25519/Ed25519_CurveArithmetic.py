"""
Ed25519 Curve Arithmetic Module
Triển khai các phép toán trên đường cong twisted Edwards: -x^2 + y^2 = 1 + dx^2y^2

Sử dụng Extended Coordinates (X:Y:Z:T) với XY = ZT
- Point (x, y) được biểu diễn là (X:Y:Z:T) với x = X/Z, y = Y/Z
- Extended coordinates cho phép complete addition law
- 9 field multiplications cho point addition (theo Hisil et al.)
"""

from .Ed25519_FieldArithmetic import FieldElement, P, D, ZERO, ONE, SQRT_M1

# Curve parameters
# Twisted Edwards curve: -x^2 + y^2 = 1 + dx^2y^2
# d = -121665/121666 mod p
# Base point B có order l = 2^252 + 27742317777372353535851937790883648493

L = 2 ** 252 + 27742317777372353535851937790883648493  # Order của base point


class EdwardsPoint:
    """
    Điểm trên đường cong twisted Edwards
    Sử dụng Extended Coordinates (X:Y:Z:T) với XY = ZT
    """

    def __init__(self, X, Y, Z, T):
        """
        Khởi tạo điểm với extended coordinates

        Args:
            X, Y, Z, T: FieldElement objects
        """
        if not all(isinstance(coord, FieldElement) for coord in [X, Y, Z, T]):
            raise TypeError("Coordinates phải là FieldElement")

        self.X = X
        self.Y = Y
        self.Z = Z
        self.T = T

    @staticmethod
    def zero():
        """Điểm trung tính (identity): (0, 1)"""
        return EdwardsPoint(
            X=ZERO.copy(),
            Y=ONE.copy(),
            Z=ONE.copy(),
            T=ZERO.copy()
        )

    @staticmethod
    def from_affine(x, y):
        """
        Tạo point từ affine coordinates (x, y)
        Extended: (X:Y:Z:T) = (x:y:1:xy)
        """
        if not isinstance(x, FieldElement) or not isinstance(y, FieldElement):
            raise TypeError("x và y phải là FieldElement")

        return EdwardsPoint(
            X=x.copy(),
            Y=y.copy(),
            Z=ONE.copy(),
            T=x.mul(y)
        )

    def to_affine(self):
        """
        Convert về affine coordinates (x, y)
        x = X/Z, y = Y/Z
        """
        if self.Z.is_zero():
            raise ValueError("Point at infinity không có affine representation")

        Z_inv = self.Z.invert()
        x = self.X.mul(Z_inv)
        y = self.Y.mul(Z_inv)
        return x, y

    def is_on_curve(self):
        """
        Kiểm tra điểm có nằm trên curve không
        -x^2 + y^2 = 1 + dx^2y^2
        """
        x, y = self.to_affine()

        x2 = x.square()
        y2 = y.square()

        # Left side: -x^2 + y^2
        left = y2.sub(x2)

        # Right side: 1 + d*x^2*y^2
        right = ONE.add(D.mul(x2).mul(y2))

        return left == right

    def __eq__(self, other):
        """
        So sánh hai điểm
        (X1:Y1:Z1:T1) == (X2:Y2:Z2:T2) nếu X1*Z2 == X2*Z1 và Y1*Z2 == Y2*Z1
        """
        if not isinstance(other, EdwardsPoint):
            return False

        # X1*Z2 == X2*Z1
        lhs1 = self.X.mul(other.Z)
        rhs1 = other.X.mul(self.Z)

        # Y1*Z2 == Y2*Z1
        lhs2 = self.Y.mul(other.Z)
        rhs2 = other.Y.mul(self.Z)

        return lhs1 == rhs1 and lhs2 == rhs2

    def __repr__(self):
        try:
            x, y = self.to_affine()
            return f"EdwardsPoint(x={x.to_int()}, y={y.to_int()})"
        except:
            return "EdwardsPoint(at infinity)"

    def add(self, other):
        """
        Cộng hai điểm sử dụng complete addition law
        Theo Hisil et al. (Section 3.1 của paper)

        Input: P1 = (X1:Y1:Z1:T1), P2 = (X2:Y2:Z2:T2)
        Output: P3 = P1 + P2 = (X3:Y3:Z3:T3)

        Cost: 9 multiplications (với precomputed table: 8M)
        """
        # A = X1 * X2
        A = self.X.mul(other.X)

        # B = Y1 * Y2
        B = self.Y.mul(other.Y)

        # C = T1 * d * T2
        C = self.T.mul(D).mul(other.T)

        # D = Z1 * Z2
        D_val = self.Z.mul(other.Z)

        # E = (X1+Y1) * (X2+Y2) - A - B
        E = (self.X.add(self.Y)).mul(other.X.add(other.Y)).sub(A).sub(B)

        # F = D - C
        F = D_val.sub(C)

        # G = D + C
        G = D_val.add(C)

        # H = B - a*A (với a = -1, nên H = B + A)
        H = B.add(A)

        # X3 = E * F
        X3 = E.mul(F)

        # Y3 = G * H
        Y3 = G.mul(H)

        # T3 = E * H
        T3 = E.mul(H)

        # Z3 = F * G
        Z3 = F.mul(G)

        return EdwardsPoint(X3, Y3, Z3, T3)

    def double(self):
        """
        Nhân đôi điểm
        Theo Hisil et al. doubling formula

        Cost: 4 multiplications + 4 squarings
        """
        # A = X1^2
        A = self.X.square()

        # B = Y1^2
        B = self.Y.square()

        # C = 2 * Z1^2
        C = self.Z.square().add(self.Z.square())

        # H = A + B
        H = A.add(B)

        # E = H - (X1+Y1)^2
        E = H.sub((self.X.add(self.Y)).square())

        # G = A - B (với a = -1)
        G = A.sub(B)

        # F = C + G
        F = C.add(G)

        # X3 = E * F
        X3 = E.mul(F)

        # Y3 = G * H
        Y3 = G.mul(H)

        # T3 = E * H
        T3 = E.mul(H)

        # Z3 = F * G
        Z3 = F.mul(G)

        return EdwardsPoint(X3, Y3, Z3, T3)

    def scalar_mul(self, scalar):
        """
        Nhân vô hướng: scalar * Point
        Sử dụng double-and-add algorithm (from left to right)

        Args:
            scalar: integer
        """
        if scalar == 0:
            return EdwardsPoint.zero()

        if scalar < 0:
            return self.neg().scalar_mul(-scalar)

        # Double-and-add
        result = EdwardsPoint.zero()
        temp = EdwardsPoint(self.X.copy(), self.Y.copy(), self.Z.copy(), self.T.copy())

        while scalar > 0:
            if scalar & 1:
                result = result.add(temp)
            temp = temp.double()
            scalar >>= 1

        return result

    def neg(self):
        """
        Phủ định điểm: -P = (-x, y)
        Trong extended coordinates: (-X, Y, Z, -T)
        """
        return EdwardsPoint(
            X=self.X.neg(),
            Y=self.Y.copy(),
            Z=self.Z.copy(),
            T=self.T.neg()
        )

    def encode(self):
        """
        Encode điểm thành 32 bytes
        Format: y-coordinate (255 bits) + sign bit của x (1 bit)

        Returns:
            bytes: 32 bytes
        """
        x, y = self.to_affine()

        # Lấy 32 bytes của y (little-endian)
        y_bytes = bytearray(y.to_bytes())

        # Set bit cao nhất là sign của x
        if x.is_negative():
            y_bytes[31] |= 0x80
        else:
            y_bytes[31] &= 0x7F

        return bytes(y_bytes)

    @staticmethod
    def decode(data):
        """
        Decode 32 bytes thành điểm

        Args:
            data: bytes (32 bytes)

        Returns:
            EdwardsPoint hoặc None nếu invalid
        """
        if len(data) != 32:
            raise ValueError("Cần đúng 32 bytes")

        data = bytearray(data)

        # Lấy sign bit
        x_sign = (data[31] & 0x80) != 0

        # Clear sign bit để lấy y
        data[31] &= 0x7F

        # Decode y
        y = FieldElement.from_bytes(bytes(data))

        # Tính x từ curve equation: x^2 = (y^2 - 1) / (d*y^2 + 1)
        y2 = y.square()

        # u = y^2 - 1
        u = y2.sub(ONE)

        # v = d*y^2 + 1
        v = D.mul(y2).add(ONE)

        # x = ±sqrt(u/v)
        # Sử dụng fast square root: x = u*v^3 * (u*v^7)^((p-5)/8)
        try:
            x = compute_sqrt_ratio(u, v)
        except:
            return None

        # Adjust sign
        if x.is_negative() != x_sign:
            x = x.neg()

        # Verify điểm có on curve không
        point = EdwardsPoint.from_affine(x, y)
        if not point.is_on_curve():
            return None

        return point

    def is_identity(self):
        """Kiểm tra có phải identity point không"""
        return self == EdwardsPoint.zero()


def compute_sqrt_ratio(u, v):
    """
    Tính sqrt(u/v) sử dụng công thức tối ưu cho p ≡ 5 (mod 8)

    Fast decompression formula từ paper Section 5:
    x = ±sqrt(u/v) = u*v^3 * (u*v^7)^((p-5)/8)

    Args:
        u, v: FieldElement

    Returns:
        FieldElement: sqrt(u/v)
    """
    # v3 = v^3
    v3 = v.square().mul(v)

    # v7 = v^7 = v3^2 * v
    v7 = v3.square().mul(v)

    # uv7 = u * v^7
    uv7 = u.mul(v7)

    # candidate = u * v^3 * (u*v^7)^((p-5)/8)
    exp = (P - 5) // 8
    pow_part = uv7.pow(exp)
    candidate = u.mul(v3).mul(pow_part)

    # Check: v * candidate^2 == u?
    check = v.mul(candidate.square())

    if check == u:
        return candidate

    # Nếu không, nhân với sqrt(-1)
    candidate = candidate.mul(SQRT_M1)

    # Verify lại
    check = v.mul(candidate.square())
    if check == u:
        return candidate

    raise ValueError("Không tồn tại căn bậc hai")


# Base point B theo Ed25519 spec
# B = (x, 4/5) với x > 0
def get_base_point():
    """
    Tạo base point B của Ed25519
    y = 4/5, x được tính từ curve equation
    """
    # y = 4/5
    y = FieldElement(value=4).mul(FieldElement(value=5).invert())

    # Tính x từ curve equation
    y2 = y.square()
    u = y2.sub(ONE)
    v = D.mul(y2).add(ONE)
    x = compute_sqrt_ratio(u, v)

    # Chọn x dương
    if x.is_negative():
        x = x.neg()

    return EdwardsPoint.from_affine(x, y)


# Cache base point
BASE_POINT = get_base_point()




# if __name__ == "__main__":
#     test_curve_arithmetic()