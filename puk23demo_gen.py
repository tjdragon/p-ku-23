import hashlib
import hmac
import os
import itertools

# --- 1. Elliptic Curve Arithmetic (Secp256k1) ---
class Secp256k1:
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    A = 0
    B = 7
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
    Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

    @classmethod
    def inverse(cls, x, n):
        return pow(x, n - 2, n)

    @classmethod
    def add(cls, p1, p2):
        if p1 is None: return p2
        if p2 is None: return p1
        (x1, y1), (x2, y2) = p1, p2
        if x1 == x2 and y1 != y2: return None
        if x1 == x2:
            lam = (3 * x1 * x1 + cls.A) * cls.inverse(2 * y1, cls.P)
        else:
            lam = (y2 - y1) * cls.inverse(x2 - x1, cls.P)
        lam %= cls.P
        x3 = (lam * lam - x1 - x2) % cls.P
        y3 = (lam * (x1 - x3) - y1) % cls.P
        return (x3, y3)

    @classmethod
    def mul(cls, k, p):
        res = None
        temp = p
        while k > 0:
            if k % 2 == 1: res = cls.add(res, temp)
            temp = cls.add(temp, temp)
            k //= 2
        return res

    @classmethod
    def g_mul(cls, k):
        return cls.mul(k, (cls.Gx, cls.Gy))

def lagrange_coeff(i, S, x, q):
    num = 1
    den = 1
    for j in S:
        if i != j:
            num = (num * (x - j)) % q
            den = (den * (i - j)) % q
    return (num * pow(den, q - 2, q)) % q

def interpolate(x, points, q):
    S = [p[0] for p in points]
    res = 0
    for i, y_i in points:
        li = lagrange_coeff(i, S, x, q)
        res = (res + li * y_i) % q
    return res

# --- 2. Party & PRSS Implementation (Fixed) ---
class Party:
    def __init__(self, id, n, t, key_share):
        self.id = id
        self.n = n
        self.t = t
        self.key_share = key_share
        self.prss_keys = {}

    def get_coeff_prss(self, A):
        # FIX: Calculate f_A(self.id) considering ALL zeros in [n] \ A
        # The polynomial must vanish at every party index not in set A.
        zeros = list(set(range(1, self.n + 1)) - set(A))
        
        num = 1
        den = 1
        # f_A(x) = Product_{z in zeros} (x - z) / (0 - z)
        # This ensures f_A(z) = 0 for all z in zeros, and f_A(0) = 1
        for z in zeros:
            num = (num * (self.id - z)) % Secp256k1.N
            den = (den * (0 - z)) % Secp256k1.N
            
        return (num * pow(den, Secp256k1.N - 2, Secp256k1.N)) % Secp256k1.N

    def get_prss_val(self, tag, purpose, counter=0):
        total = 0
        for A, key in self.prss_keys.items():
            coeff = self.get_coeff_prss(A)
            msg = f"{purpose}:{tag}:{counter}".encode()
            h = hmac.new(key, msg, hashlib.sha256).digest()
            val = int.from_bytes(h, 'big') % Secp256k1.N
            total = (total + val * coeff) % Secp256k1.N
        return total

    def get_zero_share(self, tag, counter=0):
        total = 0
        for A, key in self.prss_keys.items():
            coeff = self.get_coeff_prss(A)
            for l in range(1, self.t + 1):
                msg = f"ZERO:{tag}:{counter}:{l}".encode()
                val = int.from_bytes(hmac.new(key, msg, hashlib.sha256).digest(), 'big') % Secp256k1.N
                term = (val * pow(self.id, l, Secp256k1.N)) % Secp256k1.N
                term = (term * coeff) % Secp256k1.N
                total = (total + term) % Secp256k1.N
        return total

# --- 3. Sub-Protocols ---

def wmult(parties, a_shares, k_shares, tag_base):
    r_shares = {p.id: p.get_prss_val(tag_base + "_R", "WMULT") for p in parties}
    o_shares = {p.id: p.get_zero_share(tag_base + "_O") for p in parties}
    
    e_shares = {}
    for p in parties:
        val = (a_shares[p.id] * k_shares[p.id] + r_shares[p.id] + o_shares[p.id]) % Secp256k1.N
        e_shares[p.id] = val
        
    points = [(pid, val) for pid, val in e_shares.items()]
    e = interpolate(0, points, Secp256k1.N)
    
    w_shares = {}
    for p in parties:
        w_shares[p.id] = (e - r_shares[p.id]) % Secp256k1.N
    return w_shares

def triple_generation(parties, tag):
    a_shares = {p.id: p.get_prss_val(tag + "_a", "TRIPLE") for p in parties}
    k_shares = {p.id: p.get_prss_val(tag + "_k", "TRIPLE") for p in parties}
    r_check_shares = {p.id: p.get_prss_val(tag + "_r_check", "TRIPLE") for p in parties}
    beta_shares = {p.id: p.get_prss_val(tag + "_beta", "TRIPLE") for p in parties}
    
    w_shares = wmult(parties, a_shares, k_shares, tag + "_w")
    mu_shares = wmult(parties, r_check_shares, a_shares, tag + "_mu")
    tau_shares = wmult(parties, mu_shares, k_shares, tag + "_tau")
    
    r_val = interpolate(0, [(p.id, r_check_shares[p.id]) for p in parties], Secp256k1.N)
    beta_val = interpolate(0, [(p.id, beta_shares[p.id]) for p in parties], Secp256k1.N)
    
    T_shares = {}
    for p in parties:
        term = (tau_shares[p.id] - r_val * w_shares[p.id]) % Secp256k1.N
        T_shares[p.id] = (term * beta_val) % Secp256k1.N
        
    T_val = interpolate(0, [(pid, val) for pid, val in T_shares.items()], Secp256k1.N)
    if T_val != 0: raise Exception("Triple Verification Failed!")
        
    return a_shares, k_shares, w_shares

def presign(parties, tag):
    a, k, w = triple_generation(parties, tag)
    w_val = interpolate(0, [(p.id, w[p.id]) for p in parties], Secp256k1.N)
    
    G_shares = {p.id: Secp256k1.g_mul(k[p.id]) for p in parties}
    R_point = None
    S_ids = [p.id for p in parties]
    for p in parties:
        lam = lagrange_coeff(p.id, S_ids, 0, Secp256k1.N)
        part = Secp256k1.mul(lam, G_shares[p.id])
        R_point = Secp256k1.add(R_point, part)
        
    w_inv = Secp256k1.inverse(w_val, Secp256k1.N)
    rx = R_point[0] % Secp256k1.N 
    
    presigs = {}
    for p in parties:
        k_prime = (w_inv * a[p.id]) % Secp256k1.N
        presigs[p.id] = {'k_prime': k_prime, 'r': rx}
    return presigs

def sign(parties, message_hash, presigs, key_shares):
    o_shares = {p.id: p.get_zero_share("SIGN_NOISE") for p in parties}
    sig_shares = {}
    r = list(presigs.values())[0]['r']
    
    for p in parties:
        k_prime = presigs[p.id]['k_prime']
        x_j = key_shares[p.id]
        o_j = o_shares[p.id]
        term = (message_hash + r * x_j) % Secp256k1.N
        s_j = (k_prime * term + o_j) % Secp256k1.N
        sig_shares[p.id] = s_j
        
    s = interpolate(0, [(pid, val) for pid, val in sig_shares.items()], Secp256k1.N)
    if s > Secp256k1.N // 2: s = Secp256k1.N - s
    return r, s

# --- 4. Main Execution for n=5, t=2 ---

if __name__ == "__main__":
    n = 5
    t = 2 # Threshold: Needs 3 parties to sign, secure against 2 corrupt
    
    # Setup Keys
    secret_key = int.from_bytes(os.urandom(32), 'big') % Secp256k1.N
    public_key = Secp256k1.g_mul(secret_key)
    
    # Generate random polynomial of degree t=2
    coeffs = [secret_key] + [int.from_bytes(os.urandom(32), 'big') % Secp256k1.N for _ in range(t)]
    
    key_shares = {}
    for i in range(1, n + 1):
        # Evaluate poly at x=i
        val = 0
        for exp, c in enumerate(coeffs):
            val = (val + c * pow(i, exp, Secp256k1.N)) % Secp256k1.N
        key_shares[i] = val
        
    parties = [Party(i, n, t, key_shares[i]) for i in range(1, n + 1)]
    
    # Distribute PRSS Keys (Subsets size n-t = 3)
    subsets = list(itertools.combinations(range(1, n + 1), n - t))
    for A in subsets:
        k_A = os.urandom(32)
        for pid in A:
            parties[pid-1].prss_keys[A] = k_A
            
    print(f"Running simulation with n={n}, t={t}...")
    
    # Run
    presigs = presign(parties, "SESSION_LARGE")
    print("Presignature OK.")
    
    msg = b"Testing n=5"
    h_msg = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % Secp256k1.N
    
    r, s = sign(parties, h_msg, presigs, key_shares)
    print(f"Signature generated: r={hex(r)[:10]}...")
    
    # Verify
    s_inv = Secp256k1.inverse(s, Secp256k1.N)
    pt = Secp256k1.add(
        Secp256k1.g_mul((h_msg * s_inv) % Secp256k1.N),
        Secp256k1.mul((r * s_inv) % Secp256k1.N, public_key)
    )
    
    if pt[0] == r:
        print("Verification SUCCESS!")
    else:
        print("Verification FAILED.")