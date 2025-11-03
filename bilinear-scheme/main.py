import hashlib
import random
import time
from math import gcd
from typing import Tuple, List, Optional

# ========================
# Finite Field Arithmetic
# ========================

class FiniteField:
    def __init__(self, p: int):
        self.p = p
    
    def add(self, a: int, b: int) -> int:
        return (a + b) % self.p
    
    def sub(self, a: int, b: int) -> int:
        return (a - b) % self.p
    
    def mul(self, a: int, b: int) -> int:
        return (a * b) % self.p
    
    def pow(self, a: int, exponent: int) -> int:
        return pow(a, exponent, self.p)
    
    def inv(self, a: int) -> int:
        return pow(a, self.p - 2, self.p)

# ========================
# BN254 Curve Parameters
# ========================

# BN254 curve parameters (simplified for demonstration)
P = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47  # Curve order
CURVE_B = 3  # y² = x³ + b
A = 0  # y² = x³ + ax + b

F = FiniteField(P)

# Generator point (simplified coordinates)
G1_X = 1
G1_Y = 2

class Point:
    __slots__ = ('x', 'y', 'inf')
    
    def __init__(self, x: int = 0, y: int = 0, inf: bool = False):
        self.x = x
        self.y = y
        self.inf = inf
    
    def __eq__(self, other):
        if self.inf and other.inf:
            return True
        if self.inf or other.inf:
            return False
        return self.x == other.x and self.y == other.y
    
    def __repr__(self):
        if self.inf:
            return "Point(inf)"
        return f"Point({self.x}, {self.y})"

# ========================
# Elliptic Curve Operations
# ========================

def point_add(P1: Point, P2: Point) -> Point:
    """Add two points on the elliptic curve"""
    if P1.inf:
        return P2
    if P2.inf:
        return P1
    
    if P1.x == P2.x and P1.y != P2.y:
        return Point(inf=True)
    
    if P1.x == P2.x and P1.y == P2.y:
        # Point doubling
        if P1.y == 0:
            return Point(inf=True)
        slope = F.mul(F.add(F.mul(3, F.pow(P1.x, 2)), A), F.inv(F.mul(2, P1.y)))
    else:
        # Point addition
        if P1.x == P2.x:
            return Point(inf=True)
        slope = F.mul(F.sub(P2.y, P1.y), F.inv(F.sub(P2.x, P1.x)))
    
    x3 = F.sub(F.sub(F.pow(slope, 2), P1.x), P2.x)
    y3 = F.sub(F.mul(slope, F.sub(P1.x, x3)), P1.y)
    
    return Point(x3, y3)

def point_mul(P: Point, k: int) -> Point:
    """Scalar multiplication using double-and-add algorithm"""
    if k == 0 or P.inf:
        return Point(inf=True)
    
    result = Point(inf=True)
    addend = P
    
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    
    return result

# Generator point
G = Point(G1_X, G1_Y)

# ========================
# Bilinear Pairing (Simplified Tate Pairing)
# ========================

def tate_pairing(point_P: Point, Q: Point, n: int) -> int:
    """
    Simplified Tate pairing implementation
    Note: This is a pedagogical implementation and not secure for production
    """
    if point_P.inf or Q.inf:
        return 1
    
    # Miller's algorithm (simplified)
    f = 1
    V = point_P
    
    for i in range(n.bit_length() - 1, -1, -1):
        # Doubling step
        if V.y != 0:
            slope = F.mul(F.add(F.mul(3, F.pow(V.x, 2)), A), F.inv(F.mul(2, V.y)))
            x2 = F.sub(F.sub(F.pow(slope, 2), V.x), V.x)
            y2 = F.sub(F.mul(slope, F.sub(V.x, x2)), V.y)
            V = Point(x2, y2)
            
            # Line function
            l = F.sub(F.sub(Q.y, V.y), F.mul(slope, F.sub(Q.x, V.x)))
            f = F.mul(f, F.mul(f, l))
        
        # Addition step
        if (n >> i) & 1:
            if V.x != point_P.x:
                slope = F.mul(F.sub(point_P.y, V.y), F.inv(F.sub(point_P.x, V.x)))
                x3 = F.sub(F.sub(F.pow(slope, 2), V.x), point_P.x)
                y3 = F.sub(F.mul(slope, F.sub(V.x, x3)), V.y)
                V = Point(x3, y3)
                
                # Line function
                l = F.sub(F.sub(Q.y, V.y), F.mul(slope, F.sub(Q.x, V.x)))
                f = F.mul(f, l)
    
    # Final exponentiation (simplified)
    return F.pow(f, (P-1)//n)

# ========================
# Hash Functions
# ========================

def hash_to_point(message: bytes) -> Point:
    """Hash message to elliptic curve point (simplified)"""
    h = hashlib.sha256(message).digest()
    x = int.from_bytes(h, 'big') % P
    
    # Find y such that y² = x³ + ax + b
    rhs = F.add(F.add(F.pow(x, 3), F.mul(A, x)), CURVE_B)
    y = F.pow(rhs, (P + 1) // 4)  # Assuming P ≡ 3 mod 4
    
    return Point(x, y)

def hash_to_scalar(data: bytes) -> int:
    """Hash data to scalar value"""
    h = hashlib.sha256(data).digest()
    return int.from_bytes(h, 'big') % P

def hash_to_bytes(data: bytes, length: int) -> bytes:
    """Hash data to fixed-length bytes"""
    h = hashlib.sha256(data).digest()
    return h[:length]

# ========================
# Signcryption Scheme
# ========================

class SigncryptionScheme:
    def __init__(self):
        self.curve_order = P
        self.G = G
    
    def setup(self) -> dict:
        """System setup"""
        params = {
            'p': P,
            'g': G,
            'curve_order': P,
            'hash_to_point': hash_to_point,
            'hash_to_scalar': hash_to_scalar,
            'hash_to_bytes': hash_to_bytes,
            'pairing': tate_pairing
        }
        return params
    
    def keygen(self, params: dict) -> Tuple[int, Point]:
        """Generate key pair (sk, pk)"""
        sk = random.randint(1, params['curve_order'] - 1)
        pk = point_mul(params['g'], sk)
        return sk, pk
    
    def signcrypt(self, m: bytes, sk_sender: int, pk_receiver: Point, params: dict) -> Tuple[Point, bytes, bytes]:
        """
        Signcrypt a message
        Returns: (U, V, W) where:
        - U = r*g1
        - V = m ⊕ H2(g2^r, g2^sk_receiver)
        - W = σ = H1(m, U)^sk_sender
        """
        r = random.randint(1, params['curve_order'] - 1)
        
        # Compute U = r*g1
        U = point_mul(params['g'], r)
        
        # Compute key for encryption
        g2_r = point_mul(params['g'], r)
        g2_sk_r = point_mul(pk_receiver, r)
        key_data = f"{g2_r.x},{g2_r.y},{g2_sk_r.x},{g2_sk_r.y}".encode()
        key = params['hash_to_bytes'](key_data, 32)
        
        # Encrypt message
        V = bytes([m[i] ^ key[i % len(key)] for i in range(len(m))])
        
        # Compute signature
        sig_data = f"{m.decode()},{U.x},{U.y},{pk_receiver.x},{pk_receiver.y}".encode()
        H1 = params['hash_to_point'](sig_data)
        W = point_mul(H1, sk_sender)
        
        return U, V, W
    
    def unsigncrypt(self, ciphertext: Tuple[Point, bytes, Point], pk_sender: Point, sk_receiver: int, params: dict) -> Optional[bytes]:
        """
        Unsigncrypt a ciphertext
        Returns: message m or None if verification fails
        """
        U, V, W = ciphertext
        
        # Decrypt message
        g2_sk_r = point_mul(U, sk_receiver)
        g2_r = U
        key_data = f"{g2_r.x},{g2_r.y},{g2_sk_r.x},{g2_sk_r.y}".encode()
        key = params['hash_to_bytes'](key_data, 32)
        
        
        m = bytes([V[i] ^ key[i % len(key)] for i in range(len(V))])
        
        # Verify signature
        sig_data = f"{m.decode()},{U.x},{U.y},{pk_sender.x},{pk_sender.y}".encode()
        H1 = params['hash_to_point'](sig_data)
        
        # Check pairing equation: e(W, g) = e(H1, pk_sender)
        left_pairing = params['pairing'](W, params['g'], params['curve_order'])
        right_pairing = params['pairing'](H1, pk_sender, params['curve_order'])
        
        if left_pairing == right_pairing:
            print(m)
            return m
        else:
            return None

# ========================
# Benchmarking
# ========================

def benchmark(num_runs: int = 10):
    scheme = SigncryptionScheme()
    params = scheme.setup()
    
    print("=== BN254 Signcryption Scheme Benchmark ===")
    print(f"Running {num_runs} iterations...\n")
    
    # Key generation benchmark
    keygen_times = []
    sender_keys = []
    receiver_keys = []
    
    print("Benchmarking Key Generation...")
    for _ in range(num_runs):
        start = time.perf_counter()
        sk_sender, pk_sender = scheme.keygen(params)
        sk_receiver, pk_receiver = scheme.keygen(params)
        end = time.perf_counter()
        keygen_times.append(end - start)
        sender_keys.append((sk_sender, pk_sender))
        receiver_keys.append((sk_receiver, pk_receiver))
    
    avg_keygen = sum(keygen_times) / num_runs
    print(f"Average Key Generation Time: {avg_keygen:.6f} seconds")
    
    # Signcryption benchmark
    signcrypt_times = []
    ciphertexts = []
    test_message = b"Hello, this is a test message for signcryption!"
    
    print("\nBenchmarking Signcryption...")
    for i in range(num_runs):
        sk_sender, pk_sender = sender_keys[i]
        _, pk_receiver = receiver_keys[i]
        
        start = time.perf_counter()
        ciphertext = scheme.signcrypt(test_message, sk_sender, pk_receiver, params)
        end = time.perf_counter()
        
        signcrypt_times.append(end - start)
        ciphertexts.append(ciphertext)
    
    avg_signcrypt = sum(signcrypt_times) / num_runs
    print(f"Average Signcryption Time: {avg_signcrypt:.6f} seconds")
    
    # Unsigncryption benchmark
    unsigncrypt_times = []
    verification_success = 0
    
    print("\nBenchmarking Unsigncryption...")
    for i in range(num_runs):
        _, pk_sender = sender_keys[i]
        sk_receiver, _ = receiver_keys[i]
        ciphertext = ciphertexts[i]
        
        start = time.perf_counter()
        decrypted = scheme.unsigncrypt(ciphertext, pk_sender, sk_receiver, params)
        end = time.perf_counter()
        
        unsigncrypt_times.append(end - start)
        
        if decrypted == test_message:
            verification_success += 1
    
    avg_unsigncrypt = sum(unsigncrypt_times) / num_runs
    success_rate = (verification_success / num_runs) * 100
    
    print(f"Average Unsigncryption Time: {avg_unsigncrypt:.6f} seconds")
    print(f"Verification Success Rate: {success_rate:.1f}%")
    
    # Summary
    print("\n=== Summary ===")
    print(f"Total Operations: {num_runs}")
    print(f"Key Generation: {avg_keygen:.6f}s per operation")
    print(f"Signcryption: {avg_signcrypt:.6f}s per operation")
    print(f"Unsigncryption: {avg_unsigncrypt:.6f}s per operation")
    print(f"Overall Success Rate: {success_rate:.1f}%")

if __name__ == "__main__":
    benchmark(5)  # Reduced iterations due to computational complexity