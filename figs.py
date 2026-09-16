#!/usr/bin/env python3
"""Regenerate the Section IV figures (and the protocol diagrams) from results.json."""
import json, numpy as np, matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

R = json.load(open("results.json"))
plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 9, "axes.linewidth": 0.8,
    "axes.spines.top": False, "axes.spines.right": False,
    "figure.dpi": 600, "savefig.dpi": 600, "savefig.bbox": "tight",
})
GREY, ACC, DARK = "#9e9e9e", "#3d5a80", "#22333b"

def save(fig, name):
    fig.savefig(name, facecolor="white")
    plt.close(fig)
    print("wrote", name)

# ---- Histogram -----------------------------------------------------------
fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.6))
ax[0].bar(range(256), R["hist_plain"], width=1.0, color=DARK, linewidth=0)
ax[0].set_title("(a) Plaintext image", fontsize=9)
ax[1].bar(range(256), R["hist_cipher"], width=1.0, color=ACC, linewidth=0)
ax[1].set_title("(b) Ciphertext", fontsize=9)
for a in ax:
    a.set_xlabel("Pixel intensity"); a.set_ylabel("Frequency"); a.set_xlim(0, 255)
ax[1].axhline(1024, color="crimson", ls="--", lw=0.9, label="Expected (1024)")
ax[1].legend(frameon=False, fontsize=7.5)
save(fig, "fig11_histogram.png")

# ---- Histogram variance --------------------------------------------------
v = R["variance"]
labels = ["DES", "AES-128", "AES-256", "Proposed"]
vals = [v["des"], v["aes128"], v["aes256"], v["proposed"]]
fig, ax = plt.subplots(figsize=(4.4, 2.9))
b = ax.bar(labels, vals, color=[GREY, GREY, GREY, ACC], width=0.6, edgecolor=DARK, lw=0.6)
for r_, val in zip(b, vals):
    ax.text(r_.get_x() + r_.get_width()/2, val + 25, f"{val:.1f}", ha="center", fontsize=8)
ax.set_ylabel("Histogram variance"); ax.set_ylim(0, max(vals)*1.22)
ax.text(0.5, 0.93, f"Plaintext image: {v['plain']:,.0f}", transform=ax.transAxes,
        ha="center", fontsize=7.5, style="italic", color="dimgrey")
save(fig, "fig12_variance.png")

# ---- Chi-square ----------------------------------------------------------
c = R["chisq"]
fig, ax = plt.subplots(figsize=(4.6, 2.9))
ax.bar(["Proposed"], [c["stat"]], color=ACC, width=0.34, edgecolor=DARK, lw=0.6)
ax.axhline(c["critical_0.05"], color="crimson", ls="--", lw=1.0,
           label=f"Critical value, $\\alpha$=0.05 ({c['critical_0.05']:.2f})")
ax.axhline(255, color="green", ls=":", lw=1.0, label="Expected under uniformity (255)")
ax.text(0, c["stat"] + 8, f"{c['stat']:.2f}\n(p = {c['p']:.4f})", ha="center", fontsize=8)
ax.set_ylabel("$\\chi^2$ statistic (255 df)"); ax.set_ylim(0, c["critical_0.05"]*1.3)
ax.set_xlim(-0.6, 0.6)
ax.legend(frameon=False, fontsize=7.5, loc="lower right")
save(fig, "fig13_chisquare.png")

# ---- Entropy -------------------------------------------------------------
e = R["entropy"]
vals = [e["des"], e["aes128"], e["aes256"], e["proposed"]]
fig, ax = plt.subplots(figsize=(4.6, 2.9))
b = ax.bar(labels, vals, color=[GREY, GREY, GREY, ACC], width=0.6, edgecolor=DARK, lw=0.6)
for r_, val in zip(b, vals):
    ax.text(r_.get_x()+r_.get_width()/2, val + 0.00002, f"{val:.6f}", ha="center", fontsize=7.2)
ax.axhline(8.0, color="crimson", ls="--", lw=1.0, label="Ideal (8.0000)")
ax.set_ylabel("Shannon entropy (bits/pixel)")
ax.set_ylim(7.9988, 8.0002)
ax.ticklabel_format(axis="y", useOffset=False, style="plain")
ticks = [7.9988, 7.9991, 7.9994, 7.9997, 8.0000]
ax.set_yticks(ticks); ax.set_yticklabels([f"{t:.4f}" for t in ticks])
ax.legend(frameon=False, fontsize=7.5, loc="lower left")
save(fig, "fig14_entropy.png")

# ---- NPCR / UACI ---------------------------------------------------------
n, u = R["npcr"], R["uaci"]
fig, ax = plt.subplots(1, 2, figsize=(6.4, 2.8))
for a, m, name, unit in ((ax[0], n, "NPCR", "%"), (ax[1], u, "UACI", "%")):
    a.bar(["Measured"], [m["mean"]], yerr=[m["sd"]], capsize=4,
          color=ACC, width=0.34, edgecolor=DARK, lw=0.6)
    a.axhline(m["ideal"], color="crimson", ls="--", lw=1.0, label=f"Ideal ({m['ideal']}{unit})")
    a.set_ylabel(f"{name} ({unit})")
    lo = min(m["mean"], m["ideal"]); hi = max(m["mean"], m["ideal"])
    a.set_ylim(lo - 0.15, hi + 0.15)
    a.text(0, m["mean"], f"  {m['mean']:.4f} $\\pm$ {m['sd']:.4f}", fontsize=7.5, va="center")
    a.legend(frameon=False, fontsize=7.5, loc="lower right")
fig.suptitle(f"Mean over {n['runs']} independent encryptions", fontsize=8, y=1.02, color="dimgrey")
save(fig, "fig15_differential.png")

# ---- Throughput / latency ------------------------------------------------
t = R["throughput"]
kb = [x["kb"] for x in t]
fig, ax = plt.subplots(1, 2, figsize=(7.0, 2.8))
ax[0].plot(kb, [x["enc_kbps"] for x in t], "o-", color=ACC, ms=4, lw=1.3, label="Encryption")
ax[0].plot(kb, [x["dec_kbps"] for x in t], "s--", color=DARK, ms=4, lw=1.3, label="Decryption")
ax[0].set_xscale("log", base=2); ax[0].set_xlabel("Payload size (KB)")
ax[0].set_ylabel("Throughput (KB/s)"); ax[0].legend(frameon=False, fontsize=8)
ax[0].set_title("(a) Throughput", fontsize=9)
ax[1].plot(kb, [x["enc_s"]*1000 for x in t], "o-", color=ACC, ms=4, lw=1.3, label="Encryption")
ax[1].plot(kb, [x["dec_s"]*1000 for x in t], "s--", color=DARK, ms=4, lw=1.3, label="Decryption")
ax[1].set_xscale("log", base=2); ax[1].set_yscale("log")
ax[1].set_xlabel("Payload size (KB)"); ax[1].set_ylabel("Latency per message (ms)")
ax[1].legend(frameon=False, fontsize=8); ax[1].set_title("(b) Latency", fontsize=9)
save(fig, "fig16_speed.png")

# ================= Protocol flow diagrams =================================
def box(ax, x, y, w, h, text, fc="white", ec=DARK, fs=8.2, bold=False, ls="-"):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.012,rounding_size=0.02",
                                fc=fc, ec=ec, lw=1.0, linestyle=ls, zorder=2))
    ax.text(x+w/2, y+h/2, text, ha="center", va="center", fontsize=fs, zorder=3,
            fontweight="bold" if bold else "normal", linespacing=1.45)

def arrow(ax, p, q, style="-|>", ls="-", color=DARK, rad=0.0):
    ax.add_patch(FancyArrowPatch(p, q, arrowstyle=style, mutation_scale=11,
                                 lw=1.0, color=color, linestyle=ls, zorder=1,
                                 connectionstyle=f"arc3,rad={rad}"))

# --------- Algorithm 2 (encrypt & send) ----------------------------------
fig, ax = plt.subplots(figsize=(7.2, 5.0))
ax.set_xlim(0, 10); ax.set_ylim(0, 7.2); ax.axis("off")
L, W, H = 0.35, 2.6, 0.72
Mx = 3.65
ax.text(1.65, 6.95, "Sender  S", ha="center", fontsize=9, fontweight="bold", color=ACC)
ax.text(8.35, 6.95, "Recipient public key", ha="center", fontsize=9, fontweight="bold", color=ACC)

box(ax, L, 6.0, W, H, "Multimedia payload  $M$", fc="#eef2f7")
box(ax, L, 4.9, W, H, "Compress\n$M' = \\mathrm{Compress}(M)$")
box(ax, L, 3.55, W, H, "AES-256-GCM encrypt\n$C,\\ \\tau \\leftarrow E_K(n, M', AD)$", fc="#eef2f7")
box(ax, L, 2.2, W, H, "SHA-256 digest over\n$R\\,\\|\\,salt\\,\\|\\,AD\\,\\|\\,C\\,\\|\\,\\tau$")
box(ax, L, 0.85, W, H, "ECDSA sign with $d_S$\n$\\rightarrow \\sigma$", fc="#eef2f7")

box(ax, Mx, 6.0, W, H, "Ephemeral key pair\n$r \\in [1,n-1],\\ R = rG$")
box(ax, Mx, 4.9, W, H, "ECDH shared secret\n$Z = r\\,Q_R$")
box(ax, Mx, 3.55, W, H, "HKDF-SHA256$(Z, salt)$\n$\\rightarrow K \\,\\|\\, n$")

box(ax, 6.95, 6.0, W, H, "Validate $Q_R$\non secp256r1", ls="--")

box(ax, 3.65, 0.85, 5.9, H, "Transmitted record   $T = R \\,\\|\\, salt \\,\\|\\, AD \\,\\|\\, C \\,\\|\\, \\tau \\,\\|\\, \\sigma$",
    fc="#dbe4ee", bold=True, fs=9)
box(ax, 6.95, 3.55, W, H, "$AD = id_S \\,\\|\\, seq \\,\\|\\, ts$\n(authenticated,\nnot encrypted)", fs=7.4, ls="--")

arrow(ax, (L+W/2, 6.0), (L+W/2, 5.62))
arrow(ax, (L+W/2, 4.9), (L+W/2, 4.27))
arrow(ax, (L+W/2, 3.55), (L+W/2, 2.92))
arrow(ax, (L+W/2, 2.2), (L+W/2, 1.57))
arrow(ax, (Mx+W/2, 6.0), (Mx+W/2, 5.62))
arrow(ax, (Mx+W/2, 4.9), (Mx+W/2, 4.27))
arrow(ax, (6.95, 6.36), (Mx+W, 5.30))
arrow(ax, (Mx, 3.91), (L+W, 3.91))
arrow(ax, (6.95, 3.91), (Mx+W, 3.91))
arrow(ax, (L+W, 1.21), (3.65, 1.21))
ax.text(9.75, 0.15, "Base64 transport encoding applied to $T$ only where the transport is not binary-safe",
        ha="right", fontsize=7, style="italic", color="dimgrey")
save(fig, "fig3_encrypt.png")

# --------- Algorithm 3 (receive & decrypt) -------------------------------
fig, ax = plt.subplots(figsize=(7.2, 5.0))
ax.set_xlim(0, 10); ax.set_ylim(0, 7.2); ax.axis("off")
CX = 0.6
box(ax, CX, 6.15, 8.8, 0.62, "Received record   $T = R \\,\\|\\, salt \\,\\|\\, AD \\,\\|\\, C \\,\\|\\, \\tau \\,\\|\\, \\sigma$",
    fc="#dbe4ee", bold=True, fs=9)
steps = [
    (5.15, "Validate $R$ as a point on secp256r1"),
    (4.15, "ECDSA-Verify$(Q_S,\\ \\mathrm{SHA\\text{-}256}(\\cdot),\\ \\sigma)$"),
    (3.15, "Check $seq$ advances and $ts$ within window"),
    (2.15, "$Z = d_R R$;   HKDF$(Z, salt) \\rightarrow K \\,\\| \\, n$"),
    (1.15, "AES-256-GCM decrypt, verify tag $\\tau$"),
]
for y, txt in steps:
    box(ax, CX, y, 5.2, 0.62, txt, fc="#eef2f7" if y in (4.15, 1.15) else "white")
box(ax, CX, 0.15, 5.2, 0.62, "Decompress  $\\rightarrow$  plaintext $M$", fc="#dbe4ee", bold=True)
box(ax, 6.55, 3.05, 2.85, 1.9, "Reject:  return  $\\bot$\n\nno plaintext is released\nto the application",
    fc="#f7eeee", ec="#a03030", fs=8.2)

arrow(ax, (CX+2.6, 6.15), (CX+2.6, 5.77))
for y in (5.15, 4.15, 3.15, 2.15):
    arrow(ax, (CX+2.6, y), (CX+2.6, y-0.38))
arrow(ax, (CX+2.6, 1.15), (CX+2.6, 0.77))
for y in (5.15, 4.15, 3.15, 1.15):
    arrow(ax, (CX+5.2, y+0.31), (6.55, 4.0), color="#a03030", ls="--", rad=-0.12)
ax.text(8.0, 5.80, "any check fails", fontsize=7.6, color="#a03030", style="italic", ha="center")
save(fig, "fig4_decrypt.png")
