# A Hybrid AES GCM and Elliptic Curve Protocol for Secure and Authenticated Multimedia Communication in IoT Networks

Source code for the evaluation in the paper of the same title (submitted to *Discover Computing*, Springer Nature).

The protocol combines AES-256-GCM payload encryption, ECIES key establishment over secp256r1 (ECDH + HKDF-SHA256), and ECDSA-SHA256 origin authentication. `measure.py` implements Algorithms 1–3 from the paper and computes every quantitative result in Section IV; `figs.py` draws the figures from those results.

## Files

| File | Purpose |
| --- | --- |
| `measure.py` | Algorithms 1–3, baselines (DES, AES-128, AES-256 in CBC mode) and all metrics. Writes `results.json`. |
| `figs.py` | Reads `results.json` and writes the figures (histogram, variance, chi-square, entropy, NPCR/UACI, throughput) and the two protocol diagrams. |
| `timing.py` | Per-message timing on image, audio and video payloads from 128 KB to 10 MB, plus ECDSA sign + verify time. Writes `timing.json` and Figs 5–9 (Tables 1 and 2). Needs `ffmpeg` to create the sample video. |
| `requirements.txt` | Python dependencies. |

## Running

```bash
pip install -r requirements.txt
curl -L -o lena.png https://raw.githubusercontent.com/mikolalysenko/lena/master/lena.png
python3 measure.py     # prints the metrics and writes results.json
python3 figs.py        # writes fig3_encrypt.png ... fig16_speed.png
python3 timing.py      # writes timing.json and fig5_image.png ... fig9_signature.png
```

The test image is not included in this repository. The 512x512 greyscale benchmark was obtained from the URL above; check its terms before redistributing it.

## Measurement parameters

| Quantity | Method |
| --- | --- |
| Histogram variance, entropy, chi-square | One encryption of the 512x512 image (262,144 bytes; GCM tag excluded) |
| NPCR / UACI | Mean and standard deviation over 30 independent protocol encryptions, one-pixel plaintext change, fresh ephemeral key per message |
| Throughput / latency | Best of 5 trials, each the mean of 60 full protocol messages, at 16 KB to 4096 KB |
| Key generation, ECDH, sign, verify | Mean over 200 repetitions |
| Tables 1–2, Figs 5–9 (`timing.py`) | Payload = leading N bytes of a generated PNG, WAV or MP4 file; best of 5 trials, each the mean of 60 messages (10 in the 10 MB case). Sign + verify: mean of 200 repetitions |

Timings cover cryptographic operations only.

## Values reported in the paper

Measured with Python 3.12 and `cryptography` 46.0 on a single-core Intel Xeon (2.10 GHz, AES-NI, 4 GB RAM, Linux).

| Metric | Proposed | DES | AES-128 | AES-256 |
| --- | --- | --- | --- | --- |
| Histogram variance | 1099.84 | 1078.99 | 908.07 | 1075.12 |
| Shannon entropy (bits/pixel) | 7.999245 | 7.999260 | 7.999375 | 7.9993 |

| Metric | Value |
| --- | --- |
| Chi-square (255 df) | 274.96, p = 0.1864 (critical value 293.25 at α = 0.05) |
| NPCR | 99.6099 % |
| UACI | 33.4645 % |
| Throughput at 128 KB | 454,605 KB/s encryption, 408,885 KB/s decryption |
| ECDSA sign / verify | 0.032 ms / 0.094 ms |

Table 1 (encryption time per message, image payload, seconds; values for [16] and [17] in the paper are as reported in those works):

| Size | Proposed |
| --- | --- |
| 128 KB | 0.000284 |
| 256 KB | 0.000407 |
| 512 KB | 0.000673 |
| 1024 KB | 0.001187 |
| 10 MB | 0.010059 |

Table 2: ECDSA signature generation + verification = 0.000125 s.

`timing.json` in this repository is the raw output of the run used for Tables 1–2 and Figs 5–9.

## Reproducibility notes

- Keys, salts and nonces come from the operating-system RNG, so variance, entropy, chi-square, NPCR and UACI change slightly on every run. Expect values in the same range, not identical digits. For example, histogram variance for a uniform random 262,144-byte sample typically falls between roughly 800 and 1,300.
- Throughput depends on the CPU and on AES hardware acceleration. It will differ on other machines, and it is not representative of microcontroller-class IoT hardware.
- `npcr_fixed_nonce` in `results.json` is a control. Under a fixed key and nonce, GCM changes one ciphertext bit per changed plaintext bit, so the high NPCR comes from the per-message key establishment, not the block cipher alone.
