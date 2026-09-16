#!/usr/bin/env python3
"""
Per-message timing for Tables 1-2 and Figs 5-9.

Payloads are the leading N bytes of a sample image (PNG), audio (WAV) and
video (MP4) file generated below, at N = 128 KB, 256 KB, 512 KB, 1024 KB and
10 MB. The protocol is content-agnostic, so the three media types are expected
to give near-identical times; they are measured separately because the paper
reports them separately. Each value is the best of 5 trials, each trial the
mean of `reps` full protocol messages (encrypt_send / receive_decrypt from
measure.py). Writes timing.json and fig5-fig9 PNGs. Requires ffmpeg and lena.png.
"""
import os, json, time, wave, hashlib, subprocess
import numpy as np
from PIL import Image
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from measure import enrol, encrypt_send, receive_decrypt

SIZES_KB = [128, 256, 512, 1024, 10240]
LABELS = ["128 KB", "256 KB", "512 KB", "1024 KB", "10 MB"]
REF16 = [2.2, 2.4, 2.7, 2.9, 3.2]          # Table 1, values as reported in [16]
REF17 = [0.0114, 0.0115, 0.0232, 0.0460, 0.8700]   # Table 1, values as reported in [17]
SIG16, SIG17 = 5.24, 4.75                   # Table 2, values as reported in [16], [17]

# ---------------------------------------------------------------- sample media
def make_media():
    if not os.path.exists("sample_image.png"):
        tile = np.array(Image.open("lena.png").convert("RGB"))
        Image.fromarray(np.tile(tile, (8, 8, 1))).save("sample_image.png", compress_level=0)
    if not os.path.exists("sample_audio.wav"):
        sr, secs = 44100, 70
        t = np.arange(sr * secs) / sr
        rng = np.random.default_rng(1)
        sig = 0.4 * np.sin(2 * np.pi * 440 * t) + 0.1 * rng.standard_normal(t.size)
        pcm = (np.clip(sig, -1, 1) * 32767).astype("<i2")
        with wave.open("sample_audio.wav", "wb") as w:
            w.setnchannels(2); w.setsampwidth(2); w.setframerate(sr)
            w.writeframes(np.repeat(pcm, 2).tobytes())
    if not os.path.exists("sample_video.mp4"):
        subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-f", "lavfi", "-i",
                        "testsrc2=size=1280x720:rate=30", "-t", "20", "-b:v", "8M",
                        "-pix_fmt", "yuv420p", "sample_video.mp4"], check=True)
    files = {"image": "sample_image.png", "audio": "sample_audio.wav", "video": "sample_video.mp4"}
    for k, f in files.items():
        assert os.path.getsize(f) >= SIZES_KB[-1] * 1024, f"{f} smaller than 10 MB"
    return files

def latency(M, keys, reps, trials=5):
    d_S, Q_S, d_R, Q_R = keys
    es, ds = [], []
    for _ in range(trials):
        t = time.perf_counter()
        for _ in range(reps):
            rec = encrypt_send(M, Q_R, d_S, 1)
        es.append((time.perf_counter() - t) / reps)
        t = time.perf_counter()
        for _ in range(reps):
            assert receive_decrypt(rec, d_R, Q_S) == M
        ds.append((time.perf_counter() - t) / reps)
    return min(es), min(ds)

if __name__ == "__main__":
    files = make_media()
    d_S, Q_S = enrol(); d_R, Q_R = enrol()
    keys = (d_S, Q_S, d_R, Q_R)
    R = {"sizes_kb": SIZES_KB, "media": {}}
    for kind, f in files.items():
        data = open(f, "rb").read()
        enc, dec = [], []
        for kb in SIZES_KB:
            e, d = latency(data[:kb * 1024], keys, reps=60 if kb <= 1024 else 10)
            enc.append(e); dec.append(d)
        R["media"][kind] = {"enc_s": enc, "dec_s": dec}
        print(kind, ["%.6f" % x for x in enc], ["%.6f" % x for x in dec])

    # Table 2: ECDSA signature generation + verification on a SHA-256 digest
    dig = hashlib.sha256(os.urandom(1024)).digest()
    reps = 200
    t = time.perf_counter()
    for _ in range(reps):
        sig = d_S.sign(dig, ec.ECDSA(hashes.SHA256()))
        Q_S.verify(sig, dig, ec.ECDSA(hashes.SHA256()))
    R["sign_verify_s"] = (time.perf_counter() - t) / reps
    print("sign+verify s", R["sign_verify_s"])
    json.dump(R, open("timing.json", "w"), indent=1)

    # ------------------------------------------------------------ figures
    plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9,
                         "axes.spines.top": False, "axes.spines.right": False,
                         "savefig.dpi": 600, "savefig.bbox": "tight"})
    ACC, DARK, GREY = "#3d5a80", "#22333b", "#9e9e9e"
    x = range(len(SIZES_KB))
    for n, kind in ((5, "image"), (6, "audio"), (7, "video")):
        m = R["media"][kind]
        fig, ax = plt.subplots(figsize=(4.6, 2.9))
        ax.plot(x, [v * 1000 for v in m["enc_s"]], "o-", color=ACC, ms=4, label="Encryption")
        ax.plot(x, [v * 1000 for v in m["dec_s"]], "s--", color=DARK, ms=4, label="Decryption")
        ax.set_yscale("log"); ax.set_xticks(list(x)); ax.set_xticklabels(LABELS)
        ax.set_xlabel(f"{kind.capitalize()} payload size"); ax.set_ylabel("Time per message (ms)")
        ax.legend(frameon=False, fontsize=8)
        fig.savefig(f"fig{n}_{kind}.png", facecolor="white"); plt.close(fig)

    enc_img = R["media"]["image"]["enc_s"]
    fig, ax = plt.subplots(figsize=(4.8, 3.0))
    ax.plot(x, REF16, "o-", color="#6a994e", ms=4, label="Ref [16] (as reported)")
    ax.plot(x, REF17, "^-", color="#bc4749", ms=4, label="Ref [17] (as reported)")
    ax.plot(x, enc_img, "s-", color=ACC, ms=4, label="Proposed (measured)")
    ax.set_yscale("log"); ax.set_xticks(list(x)); ax.set_xticklabels(LABELS)
    ax.set_xlabel("Data size"); ax.set_ylabel("Encryption time (s)")
    ax.legend(frameon=False, fontsize=7.5, loc="center left", bbox_to_anchor=(0.0, 0.62))
    fig.savefig("fig8_datasize.png", facecolor="white"); plt.close(fig)

    fig, ax = plt.subplots(figsize=(4.6, 3.0))
    vals = [SIG16, SIG17, R["sign_verify_s"]]
    b = ax.bar(["Ref [16]\n(as reported)", "Ref [17]\n(as reported)", "Proposed\n(measured)"],
               vals, color=[GREY, GREY, ACC], width=0.55, edgecolor=DARK, lw=0.6)
    ax.set_yscale("log"); ax.set_ylabel("Signature generation + verification (s)")
    for r_, v in zip(b, vals):
        ax.text(r_.get_x() + r_.get_width() / 2, v * 1.25, f"{v:.2f} s" if v >= 0.01 else f"{v*1000:.3f} ms",
                ha="center", fontsize=8)
    ax.set_ylim(min(vals) / 3, max(vals) * 4)
    fig.savefig("fig9_signature.png", facecolor="white"); plt.close(fig)
    print("wrote fig5-fig9")
