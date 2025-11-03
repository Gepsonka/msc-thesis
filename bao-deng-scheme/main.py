import random
import hashlib
import time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, isPrime

def generate_p_q(k):
    """Generate parameters p, q, g where q is k-bit prime and q|(p-1)"""
    q = getPrime(k)
    p = 2 * q + 1
    while not isPrime(p):
        q = getPrime(k)
        p = 2 * q + 1
    
    # Find generator g of subgroup with order q
    while True:
        h = random.randint(2, p-2)
        g = pow(h, 2, p)  # g has order q since q|(p-1) and p=2q+1
        if g != 1:
            break
    
    return p, q, g

def aes_encrypt(key, plaintext):
    """AES-128 encryption in CBC mode with random IV"""
    iv = random.randbytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ciphertext

def aes_decrypt(key, ciphertext):
    """AES-128 decryption in CBC mode"""
    iv = ciphertext[:AES.block_size]
    ct = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

def setup(k):
    """Setup algorithm: Generate system parameters"""
    p, q, g = generate_p_q(k)
    
    # Define hash functions
    def G(K):
        K_bytes = K.to_bytes((K.bit_length() + 7) // 8, 'big')
        return hashlib.sha256(K_bytes).digest()[:16]  # 16-byte key for AES
    
    def H(data, q):
        h = hashlib.sha256(data).digest()
        return int.from_bytes(h, 'big') % q
    
    # Define symmetric encryption scheme
    SE = {
        'Enc': aes_encrypt,
        'Dec': aes_decrypt
    }
    
    param = {
        'p': p,
        'q': q,
        'g': g,
        'SE': SE,
        'G': G,
        'H': H
    }
    return param

def keygen_s(param):
    """Sender key generation"""
    q = param['q']
    p = param['p']
    g = param['g']
    
    x_S = random.randint(1, q - 1)
    y_S = pow(g, x_S, p)
    
    sk_S = (x_S, y_S)
    pk_S = y_S
    return sk_S, pk_S

def keygen_r(param):
    """Receiver key generation"""
    q = param['q']
    p = param['p']
    g = param['g']
    
    x_R = random.randint(1, q - 1)
    y_R = pow(g, x_R, p)
    
    sk_R = (x_R, y_R)
    pk_R = y_R
    return sk_R, pk_R

def signcrypt(param, sk_S, pk_R, m):
    """Signcrypt a message using Bao-Deng scheme"""
    p, q, g = param['p'], param['q'], param['g']
    SE, G, H = param['SE'], param['G'], param['H']
    
    x_S, y_S = sk_S
    y_R = pk_R
    
    # Validate receiver's public key
    if pow(y_R, q, p) != 1 or y_R == 1:
        return None
    
    # Random ephemeral key
    x = random.randint(1, q - 1)
    K = pow(y_R, x, p)
    omega = pow(g, x, p)  # New element: ω = g^x
    tau = G(K)
    
    # Prepare binding data (same as before)
    elem_len = (p.bit_length() + 7) // 8
    bind = y_S.to_bytes(elem_len, 'big') + y_R.to_bytes(elem_len, 'big')
    
    # Compute r = H(m || bind || ω) [DIFFERENT from Zheng: uses ω instead of K]
    omega_bytes = omega.to_bytes(elem_len, 'big')
    r = H(m + bind + omega_bytes, q)
    
    # Encrypt message
    c = SE['Enc'](tau, m)
    
    # Check for division by zero
    if (r + x_S) % q == 0:
        return None
    
    # Compute s = x/(r + x_S) mod q
    s = (x * pow(r + x_S, -1, q)) % q
    
    return (c, r, s)

def unsigncrypt(param, pk_S, sk_R, C):
    """Unsigncrypt a ciphertext using Bao-Deng scheme"""
    p, q, g = param['p'], param['q'], param['g']
    SE, G, H = param['SE'], param['G'], param['H']
    
    x_R, y_R = sk_R
    y_S = pk_S
    
    # Validate sender's public key
    if pow(y_S, q, p) != 1 or y_S == 1:
        return None
    
    # Parse ciphertext
    c, r, s = C
    if not (0 <= r < q and 0 <= s < q):
        return None
    
    # Compute ω = (y_S * g^r)^s mod p
    g_r = pow(g, r, p)
    y_S_g_r = (y_S * g_r) % p
    omega = pow(y_S_g_r, s, p)
    
    # Recover key K and decrypt
    K = pow(omega, x_R, p)
    tau = G(K)
    try:
        m = SE['Dec'](tau, c)
    except (ValueError, KeyError):
        return None
    
    # Verify binding (same as before)
    elem_len = (p.bit_length() + 7) // 8
    bind = y_S.to_bytes(elem_len, 'big') + y_R.to_bytes(elem_len, 'big')
    omega_bytes = omega.to_bytes(elem_len, 'big')
    expected_r = H(m + bind + omega_bytes, q)  # Use ω instead of K in hash
    
    return m if expected_r == r else None

def benchmark(k=128, iterations=100, msg_sizes=None):
    """Benchmark the Bao-Deng signcryption scheme"""
    if msg_sizes is None:
        msg_sizes = [64, 256, 1024, 4096, 16384]  # bytes
    
    print(f"\n{'='*60}")
    print(f"Bao-Deng Signcryption Benchmark (Security parameter: {k}-bit)")
    print(f"{'='*60}")
    
    # 1. Setup time
    start = time.perf_counter()
    param = setup(k)
    setup_time = time.perf_counter() - start
    print(f"Setup time: {setup_time*1000:.2f} ms")
    
    # 2. Key generation times
    start = time.perf_counter()
    sk_S, pk_S = keygen_s(param)
    keygen_s_time = time.perf_counter() - start
    
    start = time.perf_counter()
    sk_R, pk_R = keygen_r(param)
    keygen_r_time = time.perf_counter() - start
    
    print(f"Sender keygen time: {keygen_s_time*1000:.4f} ms")
    print(f"Receiver keygen time: {keygen_r_time*1000:.4f} ms")
    
    # 3. Signcryption/Unsigncryption times for different message sizes
    print(f"\n{'Message Size':<15}{'Signcrypt (ms)':<20}{'Unsigncrypt (ms)':<20}{'Success Rate':<15}")
    print("-"*60)
    
    for size in msg_sizes:
        msg = b'Benchmark data' * (size // 13 + 1)
        msg = msg[:size]
        
        signcrypt_times = []
        unsigncrypt_times = []
        success_count = 0
        
        # Warm-up run
        C = signcrypt(param, sk_S, pk_R, msg)
        if C:
            unsigncrypt(param, pk_S, sk_R, C)
        
        for _ in range(iterations):
            # Signcryption
            start = time.perf_counter()
            C = signcrypt(param, sk_S, pk_R, msg)
            signcrypt_time = time.perf_counter() - start
            
            if C is None:
                continue
                
            # Unsigncryption
            start = time.perf_counter()
            m = unsigncrypt(param, pk_S, sk_R, C)
            unsigncrypt_time = time.perf_counter() - start
            
            # Verify correctness
            if m == msg:
                success_count += 1
                signcrypt_times.append(signcrypt_time)
                unsigncrypt_times.append(unsigncrypt_time)
        
        avg_signcrypt = (sum(signcrypt_times) / len(signcrypt_times) * 1000) if signcrypt_times else 0
        avg_unsigncrypt = (sum(unsigncrypt_times) / len(unsigncrypt_times) * 1000) if unsigncrypt_times else 0
        success_rate = success_count / iterations * 100
        
        print(f"{size:<15}{avg_signcrypt:<20.4f}{avg_unsigncrypt:<20.4f}{success_rate:<15.1f}%")
    
    # 4. Throughput calculation
    print(f"\nThroughput (for 1KB messages):")
    avg_1kb_signcrypt = [t for t in signcrypt_times if len(signcrypt_times) > 0][-1] * 1000
    print(f"Signcryption throughput: {1024 / (avg_1kb_signcrypt/1000):.2f} KB/s")
    
    avg_1kb_unsigncrypt = [t for t in unsigncrypt_times if len(unsigncrypt_times) > 0][-1] * 1000
    print(f"Unsigncryption throughput: {1024 / (avg_1kb_unsigncrypt/1000):.2f} KB/s")

# Example usage and benchmark
if __name__ == "__main__":
    # 1. Run small example for verification
    print("Running verification example with k=64...")
    param = setup(64)
    sk_S, pk_S = keygen_s(param)
    sk_R, pk_R = keygen_r(param)
    
    message = b"Hello, this is a test message!"
    ciphertext = signcrypt(param, sk_S, pk_R, message)
    
    if ciphertext:
        decrypted = unsigncrypt(param, pk_S, sk_R, ciphertext)
        print(f"Original message: {message}")
        print(f"Decrypted message: {decrypted}")
        print("Verification: ", "SUCCESS" if decrypted == message else "FAILED")
    else:
        print("Signcryption failed in verification example")
    
    # 2. Run comprehensive benchmark
    benchmark(k=128, iterations=50, msg_sizes=[64, 256, 1024, 4096, 16384])