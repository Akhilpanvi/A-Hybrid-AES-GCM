#!/usr/bin/env python3
"""
Measurement script for "A Hybrid AES GCM and Elliptic Curve Protocol for
Secure and Authenticated Multimedia Communication in IoT Networks".

Implements Algorithms 1-3 (AES-256-GCM, ECIES over secp256r1 with HKDF-SHA256,
ECDSA-SHA256) and produces every quantitative value reported in Section IV.
Keys, salts and nonces are drawn fresh from the OS RNG on every run, so the
statistical metrics vary slightly between runs; throughput depends on hardware.
Writes results.json.
"""
import os, json, time, hashlib, statistics
import numpy as np
from PIL import Image
from scipy.stats import chi2

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES

CURVE = ec.SECP256R1()
RESULTS = {}

# ---------------------------------------------------------------- Algorithm 1
def enrol():
    d = ec.generate_private_key(CURVE)
    return d, d.public_key()

# ---------------------------------------------------------------- Algorithm 2
def encrypt_send(M, Q_R, d_S, seq, device_id=b"dev-01"):
    r = ec.generate_private_key(CURVE)                 # ephemeral
    R = r.public_key()
    shared = r.exchange(ec.ECDH(), Q_R)
    salt = os.urandom(16)
    k = HKDF(algorithm=hashes.SHA256(), length=44, salt=salt,
             info=b"ecies-aes256gcm").derive(shared)
    key, nonce = k[:32], k[32:44]
    ts = int(time.time()).to_bytes(8, "big")
    AD = device_id + seq.to_bytes(8, "big") + ts
    C = AESGCM(key).encrypt(nonce, M, AD)
    Rb = R.public_bytes(serialization.Encoding.X962,
                        serialization.PublicFormat.UncompressedPoint)
    digest = hashlib.sha256(Rb + salt + AD + C).digest()
    sig = d_S.sign(digest, ec.ECDSA(hashes.SHA256()))
    return {"R": Rb, "salt": salt, "AD": AD, "C": C, "sig": sig}

# ---------------------------------------------------------------- Algorithm 3
def receive_decrypt(T, d_R, Q_S):
    digest = hashlib.sha256(T["R"] + T["salt"] + T["AD"] + T["C"]).digest()
    Q_S.verify(T["sig"], digest, ec.ECDSA(hashes.SHA256()))   # raises on failure
    R = ec.EllipticCurvePublicKey.from_encoded_point(CURVE, T["R"])
    shared = d_R.exchange(ec.ECDH(), R)
    k = HKDF(algorithm=hashes.SHA256(), length=44, salt=T["salt"],
             info=b"ecies-aes256gcm").derive(shared)
    return AESGCM(k[:32]).decrypt(k[32:44], T["C"], T["AD"])

# ---------------------------------------------------------------- baselines
def aes_cbc(data, keylen):
    key, iv = os.urandom(keylen), os.urandom(16)
    pad = 16 - len(data) % 16
    data = data + bytes([pad]) * pad
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()

def des_cbc(data):
    k = os.urandom(8)
    key, iv = k * 3, os.urandom(8)          # K1=K2=K3 == single DES
    pad = 8 - len(data) % 8
    data = data + bytes([pad]) * pad
    e = Cipher(TripleDES(key), modes.CBC(iv)).encryptor()
    return e.update(data) + e.finalize()

# ---------------------------------------------------------------- metrics
def hist(b):
    return np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256)[:256]

def variance(b):
    return float(np.var(hist(b).astype(float)))

def entropy(b):
    h = hist(b).astype(float); p = h / h.sum(); p = p[p > 0]
    return float(-np.sum(p * np.log2(p)))

def chisq(b, npix):
    h = hist(b).astype(float)[:256]
    exp = npix / 256.0
    stat = float(np.sum((h - exp) ** 2) / exp)
    return stat, float(chi2.sf(stat, 255))

if __name__ == "__main__":
    # ------------------------------------------------------------ load image
    img = Image.open("lena.png").convert("L").resize((512, 512))
    P = np.array(img, dtype=np.uint8)
    plain = P.tobytes()
    NPIX = P.size
    print(f"Benchmark image: 512x512 grayscale, {NPIX} pixels")

    d_S, Q_S = enrol()
    d_R, Q_R = enrol()

    # ---- ciphertexts (GCM tag trimmed so histograms cover exactly NPIX bytes)
    T = encrypt_send(plain, Q_R, d_S, 1)
    assert receive_decrypt(T, d_R, Q_S) == plain, "round-trip failed"
    ct_prop = T["C"][:NPIX]
    ct_des = des_cbc(plain)[:NPIX]
    ct_a128 = aes_cbc(plain, 16)[:NPIX]
    ct_a256 = aes_cbc(plain, 32)[:NPIX]

    RESULTS["variance"] = {
        "proposed": variance(ct_prop), "des": variance(ct_des),
        "aes128": variance(ct_a128), "aes256": variance(ct_a256),
        "plain": variance(plain)}
    RESULTS["entropy"] = {
        "proposed": entropy(ct_prop), "des": entropy(ct_des),
        "aes128": entropy(ct_a128), "aes256": entropy(ct_a256),
        "plain": entropy(plain)}
    stat, p = chisq(ct_prop, NPIX)
    RESULTS["chisq"] = {"stat": stat, "p": p, "critical_0.05": float(chi2.ppf(0.95, 255)),
                        "df": 255, "expected_per_bin": NPIX / 256.0}

    # ------------------------------------------------------------ NPCR / UACI
    # Protocol level: a one-pixel plaintext change, re-encrypted under the
    # protocol (fresh ephemeral key per message, Algorithm 2 step 3).
    P2 = P.copy(); P2[256, 256] = (int(P2[256, 256]) + 1) % 256
    plain2 = P2.tobytes()
    n_runs = 30
    npcrs, uacis = [], []
    for _ in range(n_runs):
        c1 = np.frombuffer(encrypt_send(plain, Q_R, d_S, 1)["C"][:NPIX], dtype=np.uint8)
        c2 = np.frombuffer(encrypt_send(plain2, Q_R, d_S, 2)["C"][:NPIX], dtype=np.uint8)
        npcrs.append(float(np.mean(c1 != c2) * 100))
        uacis.append(float(np.mean(np.abs(c1.astype(int) - c2.astype(int))) / 255 * 100))
    RESULTS["npcr"] = {"mean": statistics.mean(npcrs), "sd": statistics.pstdev(npcrs),
                       "ideal": 99.6094, "runs": n_runs}
    RESULTS["uaci"] = {"mean": statistics.mean(uacis), "sd": statistics.pstdev(uacis),
                       "ideal": 33.4635, "runs": n_runs}

    # Fixed-key/nonce control: isolates the diffusion of the mode itself.
    key, nonce = os.urandom(32), os.urandom(12)
    f1 = np.frombuffer(AESGCM(key).encrypt(nonce, plain, None)[:NPIX], dtype=np.uint8)
    f2 = np.frombuffer(AESGCM(key).encrypt(nonce, plain2, None)[:NPIX], dtype=np.uint8)
    RESULTS["npcr_fixed_nonce"] = float(np.mean(f1 != f2) * 100)

    # ------------------------------------------------------------ throughput
    # Best of `trials` trials, each averaging `reps` full protocol messages
    # (encrypt_send / receive_decrypt), to suppress scheduler noise.
    def bench(nbytes, reps=60, trials=5):
        M = os.urandom(nbytes); es, ds = [], []
        for _ in range(trials):
            t = time.perf_counter()
            for _ in range(reps):
                rec = encrypt_send(M, Q_R, d_S, 1)
            es.append((time.perf_counter() - t) / reps)
            t = time.perf_counter()
            for _ in range(reps):
                receive_decrypt(rec, d_R, Q_S)
            ds.append((time.perf_counter() - t) / reps)
        kb = nbytes / 1024; enc = min(es); dec = min(ds)
        return {"kb": kb, "enc_s": enc, "dec_s": dec,
                "enc_kbps": kb / enc, "dec_kbps": kb / dec}

    RESULTS["throughput"] = [bench(s * 1024) for s in (16, 32, 64, 128, 256, 512, 1024, 4096)]

    # ------------------------------------------------------------ primitives
    def timeit(fn, reps=200):
        t = time.perf_counter()
        for _ in range(reps):
            fn()
        return (time.perf_counter() - t) / reps

    msg = os.urandom(1024)
    dig = hashlib.sha256(msg).digest()
    sig = d_S.sign(dig, ec.ECDSA(hashes.SHA256()))
    RESULTS["primitives"] = {
        "keygen_s": timeit(lambda: ec.generate_private_key(CURVE)),
        "ecdh_s": timeit(lambda: d_S.exchange(ec.ECDH(), Q_R)),
        "sign_s": timeit(lambda: d_S.sign(dig, ec.ECDSA(hashes.SHA256()))),
        "verify_s": timeit(lambda: Q_S.verify(sig, dig, ec.ECDSA(hashes.SHA256()))),
    }

    # ------------------------------------------------------------ histograms
    RESULTS["hist_plain"] = hist(plain).tolist()
    RESULTS["hist_cipher"] = hist(ct_prop).tolist()

    json.dump(RESULTS, open("results.json", "w"), indent=1)

    print("\n=== VARIANCE ==="); [print(f"  {k:9s} {v:12.2f}") for k, v in RESULTS["variance"].items()]
    print("=== ENTROPY ==="); [print(f"  {k:9s} {v:.6f}") for k, v in RESULTS["entropy"].items()]
    print(f"=== CHI-SQ === stat={stat:.2f} p={p:.4f} crit={RESULTS['chisq']['critical_0.05']:.2f}")
    print(f"=== NPCR === {RESULTS['npcr']['mean']:.4f} % (sd {RESULTS['npcr']['sd']:.4f})")
    print(f"=== UACI === {RESULTS['uaci']['mean']:.4f} % (sd {RESULTS['uaci']['sd']:.4f})")
    print(f"=== NPCR fixed nonce (control) === {RESULTS['npcr_fixed_nonce']:.6f} %")
    print("=== THROUGHPUT ===")
    for r in RESULTS["throughput"]:
        print(f"  {r['kb']:8.0f} KB  enc {r['enc_kbps']:12.1f} KB/s   dec {r['dec_kbps']:12.1f} KB/s")
    print("=== PRIMITIVES (ms) ===")
    for k, v in RESULTS["primitives"].items():
        print(f"  {k:10s} {v*1000:.4f}")
