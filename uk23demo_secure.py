import hashlib
import hmac
import os
import itertools
from ecdsa import SECP256k1
from ecdsa.ellipticcurve import Point
from ecdsa.numbertheory import inverse_mod

# --- 1. Elliptic Curve Arithmetic (using ecdsa lib) ---
class Secp256k1Interface:
    # Constants from the curve
    curve = SECP256k1.curve
    generator = SECP256k1.generator
    order = SECP256k1.order
    
    P = curve.p()
    N = order
    
    @classmethod
    def inverse(cls, x, n):
        return inverse_mod(x, n)

    @classmethod
    def add(cls, p1, p2):
        if p1 is None: return p2
        if p2 is None: return p1
        return p1 + p2

    @classmethod
    def mul(cls, k, p):
        if p is None: return None
        return k * p

    @classmethod
    def g_mul(cls, k):
        return k * cls.generator

def lagrange_coeff(i, S, x, q):
    num = 1
    den = 1
    for j in S:
        if i != j:
            num = (num * (x - j)) % q
            den = (den * (i - j)) % q
    return (num * inverse_mod(den, q)) % q

def interpolate(x, points, q):
    S = [p[0] for p in points]
    res = 0
    for i, y_i in points:
        li = lagrange_coeff(i, S, x, q)
        res = (res + li * y_i) % q
    return res

# --- 2. Party & PRSS Implementation ---
class Party:
    def __init__(self, id, n, t, key_share):
        self.id = id
        self.n = n
        self.t = t
        self.key_share = key_share
        self.prss_keys = {}  # Keys for subsets of size n-t

    def get_coeff_prss(self, A):
        # Calculate f_A(self.id) for polynomial f_A defined by subset A.
        # f_A(0)=1, f_A(k)=0 for k in [n]\A.
        zero_node = list(set(range(1, self.n + 1)) - set(A))[0]
        num = (self.id - zero_node) 
        den = (0 - zero_node)
        return (num * inverse_mod(den, Secp256k1Interface.N)) % Secp256k1Interface.N

    def get_prss_val(self, tag, purpose, counter=0):
        # Generates a share of a random value using PRSS
        total = 0
        for A, key in self.prss_keys.items():
            coeff = self.get_coeff_prss(A)
            msg = f"{purpose}:{tag}:{counter}".encode()
            # PRF output
            h = hmac.new(key, msg, hashlib.sha256).digest()
            val = int.from_bytes(h, 'big') % Secp256k1Interface.N
            total = (total + val * coeff) % Secp256k1Interface.N
        return total

    def get_zero_share(self, tag, counter=0):
        # Generates a share of ZERO using PRZS
        total = 0
        for A, key in self.prss_keys.items():
            coeff = self.get_coeff_prss(A)
            for l in range(1, self.t + 1):
                msg = f"ZERO:{tag}:{counter}:{l}".encode()
                val = int.from_bytes(hmac.new(key, msg, hashlib.sha256).digest(), 'big') % Secp256k1Interface.N
                term = (val * pow(self.id, l, Secp256k1Interface.N)) % Secp256k1Interface.N
                term = (term * coeff) % Secp256k1Interface.N
                total = (total + term) % Secp256k1Interface.N
        return total

# --- 3. Sub-Protocols (Weak Mult & Triple) ---

def wmult(parties, a_shares, k_shares, tag_base):
    # Implements Protocol Pi_wmult
    # 1. Get random r (degree t) and o (degree 2t, zero)
    r_shares = {p.id: p.get_prss_val(tag_base + "_R", "WMULT") for p in parties}
    o_shares = {p.id: p.get_zero_share(tag_base + "_O") for p in parties}
    
    # 2. Compute and Broadcast e_j = a_j * k_j + r_j + o_j
    e_shares = {}
    for p in parties:
        val = (a_shares[p.id] * k_shares[p.id] + r_shares[p.id] + o_shares[p.id]) % Secp256k1Interface.N
        e_shares[p.id] = val
        
    # 3. Reconstruct e (degree 2t, requires 2t+1=3 points)
    points = [(pid, val) for pid, val in e_shares.items()]
    e = interpolate(0, points, Secp256k1Interface.N)
    
    # 4. Output w_j = e - r_j
    w_shares = {}
    for p in parties:
        w_shares[p.id] = (e - r_shares[p.id]) % Secp256k1Interface.N
    return w_shares

def triple_generation(parties, tag):
    # Implements Protocol Pi_triple
    # 1. Generate shares of random a, k, r, beta
    a_shares = {p.id: p.get_prss_val(tag + "_a", "TRIPLE") for p in parties}
    k_shares = {p.id: p.get_prss_val(tag + "_k", "TRIPLE") for p in parties}
    r_check_shares = {p.id: p.get_prss_val(tag + "_r_check", "TRIPLE") for p in parties}
    beta_shares = {p.id: p.get_prss_val(tag + "_beta", "TRIPLE") for p in parties}
    
    # 2. Perform Weak Multiplications
    w_shares = wmult(parties, a_shares, k_shares, tag + "_w") # w = a*k
    mu_shares = wmult(parties, r_check_shares, a_shares, tag + "_mu") # mu = r_check*a
    tau_shares = wmult(parties, mu_shares, k_shares, tag + "_tau") # tau = mu*k = r_check*a*k
    
    # 3. Reveal r_check and beta
    r_val = interpolate(0, [(p.id, r_check_shares[p.id]) for p in parties], Secp256k1Interface.N)
    beta_val = interpolate(0, [(p.id, beta_shares[p.id]) for p in parties], Secp256k1Interface.N)
    
    # 4. Batch Verification check: T = Sum (tau - r*w) * beta^i == 0
    T_shares = {}
    for p in parties:
        term = (tau_shares[p.id] - r_val * w_shares[p.id]) % Secp256k1Interface.N
        T_shares[p.id] = (term * beta_val) % Secp256k1Interface.N
        
    T_val = interpolate(0, [(pid, val) for pid, val in T_shares.items()], Secp256k1Interface.N)
    if T_val != 0: raise Exception("Triple Verification Failed!")
        
    return a_shares, k_shares, w_shares

# --- 4. Main ECDSA Protocol ---

def presign(parties, tag):
    # Implements Presigning
    # 1. Get verified triple (a, k, w) where w = k*a
    a, k, w = triple_generation(parties, tag)
    
    # 2. Reveal w (value of k*a)
    w_val = interpolate(0, [(p.id, w[p.id]) for p in parties], Secp256k1Interface.N)
    
    # 3. Exchange G_j = g^(k_j) and reconstruct R = g^k
    # Note: R is reconstructed via interpolation in the exponent
    G_shares = {p.id: Secp256k1Interface.g_mul(k[p.id]) for p in parties}
    
    R_point = None # Identity
    S_ids = [p.id for p in parties]
    for p in parties:
        # Lagrange coeff for party p at x=0
        lam = lagrange_coeff(p.id, S_ids, 0, Secp256k1Interface.N)
        # part = G_j ^ lambda_j
        part = Secp256k1Interface.mul(lam, G_shares[p.id])
        R_point = Secp256k1Interface.add(R_point, part)
        
    # 4. Compute shares of k' = k^{-1} = w^{-1} * a
    w_inv = Secp256k1Interface.inverse(w_val, Secp256k1Interface.N)
    # R_point is an ecdsa Point object, we need the x coordinate
    rx = R_point.x() % Secp256k1Interface.N 
    
    presigs = {}
    for p in parties:
        # k'_j = w^{-1} * a_j
        k_prime = (w_inv * a[p.id]) % Secp256k1Interface.N
        presigs[p.id] = {'k_prime': k_prime, 'r': rx}
    return presigs

def sign(parties, message_hash, presigs, key_shares):
    # Implements Signing
    # s_j = k'_j * (h + r * x_j) + o_j
    
    # Fresh Zero share for masking
    o_shares = {p.id: p.get_zero_share("SIGN_NOISE") for p in parties}
    
    sig_shares = {}
    r = list(presigs.values())[0]['r']
    
    for p in parties:
        k_prime = presigs[p.id]['k_prime']
        x_j = key_shares[p.id]
        o_j = o_shares[p.id]
        
        term = (message_hash + r * x_j) % Secp256k1Interface.N
        s_j = (k_prime * term + o_j) % Secp256k1Interface.N
        sig_shares[p.id] = s_j
        
    # Coordinator Reconstructs s (interpolate degree 2t)
    s = interpolate(0, [(pid, val) for pid, val in sig_shares.items()], Secp256k1Interface.N)
    
    # Normalization (canonical s)
    if s > Secp256k1Interface.N // 2: s = Secp256k1Interface.N - s
        
    return r, s

# --- 5. Demonstration ---

if __name__ == "__main__":
    n = 3; t = 1
    
    # A. Key Generation (Simulated Dealer)
    secret_key = int.from_bytes(os.urandom(32), 'big') % Secp256k1Interface.N
    public_key = Secp256k1Interface.g_mul(secret_key)
    
    # Shamir Sharing of secret_key (degree t=1)
    # f(x) = secret + a1*x
    poly_coeff = [secret_key, int.from_bytes(os.urandom(32), 'big') % Secp256k1Interface.N]
    key_shares = {}
    for i in range(1, n + 1):
        key_shares[i] = (poly_coeff[0] + poly_coeff[1] * i) % Secp256k1Interface.N
        
    # Initialize Parties
    parties = [Party(i, n, t, key_shares[i]) for i in range(1, n + 1)]
    
    # Distribute PRSS Keys (for every subset of size n-t=2)
    subsets = list(itertools.combinations(range(1, n + 1), n - t))
    for A in subsets:
        k_A = os.urandom(32)
        for pid in A:
            parties[pid-1].prss_keys[A] = k_A

    print("--- Setup Complete ---")
    print(f"Parties: {n}, Threshold: {t}")
    
    # B. Presigning Phase
    # Generates a presignature independent of the message
    print("\n--- Phase 1: Presigning ---")
    presigs = presign(parties, "SESSION_1")
    r_val = presigs[1]['r']
    print(f"Presignature generated (r): {hex(r_val)[:10]}...")

    # C. Signing Phase
    print("\n--- Phase 2: Signing ---")
    msg = b"Honest Majority ECDSA"
    h_msg = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % Secp256k1Interface.N
    print(f"Message: {msg}")
    
    r_sig, s_sig = sign(parties, h_msg, presigs, key_shares)
    print(f"Signature (r, s):\n  r: {hex(r_sig)}\n  s: {hex(s_sig)}")
    
    # D. Verification
    print("\n--- Phase 3: Verification ---")
    s_inv = Secp256k1Interface.inverse(s_sig, Secp256k1Interface.N)
    u1 = (h_msg * s_inv) % Secp256k1Interface.N
    u2 = (r_sig * s_inv) % Secp256k1Interface.N
    
    # Calculate R' = u1*G + u2*Public_Key
    pt1 = Secp256k1Interface.g_mul(u1)
    pt2 = Secp256k1Interface.mul(u2, public_key)
    R_prime = Secp256k1Interface.add(pt1, pt2)
    
    if R_prime.x() == r_sig:
        print("SUCCESS: Signature Verified!")
    else:
        print("FAILURE: Invalid Signature")
