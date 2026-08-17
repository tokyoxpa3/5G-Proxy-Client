# -*- coding: utf-8 -*-
"""
5G-Proxy-Client / 5G-Proxy-Pro 圖文教學 — 架構圖產生器
執行：python docs/gen_figures.py
輸出：docs/figures/fig1_architecture.png
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import (FancyBboxPatch, Circle, Polygon,
                                FancyArrowPatch, Ellipse, Rectangle)

plt.rcParams["font.sans-serif"] = ["Microsoft JhengHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "figures")
os.makedirs(OUT, exist_ok=True)

C_ACCENT = "#D9534F"
C_WIFI = "#1565C0"
C_5G = "#00695C"
C_SUB = "#6C757D"


def rbox(ax, x, y, w, h, fc, ec, radius=0.1, lw=1.5, zorder=2):
    ax.add_patch(FancyBboxPatch((x, y), w, h,
                 boxstyle=f"round,pad=0,rounding_size={radius}",
                 facecolor=fc, edgecolor=ec, linewidth=lw, zorder=zorder))


def txt(ax, x, y, s, size=10, color="#212529", ha="center", va="center",
        weight="normal", bbox=None, zorder=6):
    ax.text(x, y, s, fontsize=size, color=color, ha=ha, va=va,
            fontweight=weight, zorder=zorder, bbox=bbox)


def arrow(ax, x1, y1, x2, y2, color="#ADB5BD", lw=2.2, ls="-", style="-|>",
          zorder=5, shrinkA=2, shrinkB=2):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style,
                 color=color, linewidth=lw, linestyle=ls, mutation_scale=16,
                 zorder=zorder, shrinkA=shrinkA, shrinkB=shrinkB))


def num_badge(ax, x, y, n, r=0.24, size=13):
    ax.add_patch(Circle((x, y), r, facecolor=C_ACCENT, edgecolor="white",
                        linewidth=1.5, zorder=10))
    ax.text(x, y, str(n), color="white", ha="center", va="center",
            fontsize=size, fontweight="bold", zorder=11)


def phone(ax, x, y, w, h, title, accent):
    rbox(ax, x - 0.14, y - 0.14, w + 0.28, h + 0.28, "#111111", "#111111",
         radius=0.12, zorder=1)
    rbox(ax, x, y, w, h, "#FFFFFF", "#E0E0E0", radius=0.05, lw=1, zorder=2)
    ax.add_patch(Rectangle((x, y + h - 0.3), w, 0.3, facecolor="#EEEEEE",
                           edgecolor="none", zorder=3))
    txt(ax, x + w - 0.2, y + h - 0.15, "10:24", size=6.5, color="#333", ha="right")
    txt(ax, x + 0.16, y + h - 0.15, "5G", size=6, color=C_5G, ha="left",
        weight="bold")
    txt(ax, x + w / 2, y + h - 0.72, title, size=11.5, weight="bold")
    return y + h - 0.95


def fig1():
    fig, ax = plt.subplots(figsize=(14.5, 8.4), dpi=150)
    ax.set_xlim(0, 14.5); ax.set_ylim(0, 8.4); ax.axis("off")
    ax.set_facecolor("#FDFDFD")

    # ---- Client 手機 ----
    phone(ax, 0.35, 2.6, 1.95, 4.1, "5G Proxy Client", C_ACCENT)
    txt(ax, 0.55, 5.35, "SOCKS5 Server", size=7.5, ha="left")
    rbox(ax, 0.55, 4.9, 1.55, 0.26, "#E8F0FE", C_WIFI, radius=0.03, lw=1)
    txt(ax, 1.325, 5.03, "192.168.1.178", size=7.5, color=C_WIFI)
    rbox(ax, 0.55, 4.4, 1.55, 0.26, "#E8F0FE", C_WIFI, radius=0.03, lw=1)
    txt(ax, 1.325, 4.53, "1080", size=7.5, color=C_WIFI)
    rbox(ax, 0.55, 3.55, 1.55, 0.3, "#4CAF50", "#4CAF50", radius=0.05)
    txt(ax, 1.325, 3.7, "Start Tunnel", size=7.5, color="white", weight="bold")
    txt(ax, 0.55, 2.95, "Tunnel active", size=7.5, color="#2E7D32", ha="left",
        weight="bold")
    txt(ax, 0.35, 2.35, "Client 手機", size=10.5, color=C_SUB)
    txt(ax, 0.35, 2.05, "Wi-Fi IP: 192.168.1.192", size=9.5, color=C_WIFI,
        weight="bold")
    num_badge(ax, 0.3, 7.6, 1)

    # ---- TUN ----
    rbox(ax, 2.85, 4.3, 2.05, 1.7, "#E3F2FD", "#64B5F6", radius=0.12)
    txt(ax, 3.875, 5.5, "TUN 虛擬網卡", size=11, color="#0D47A1", weight="bold")
    txt(ax, 3.875, 5.05, "10.8.0.2/32", size=9.5, color="#1565C0")
    txt(ax, 3.875, 4.65, "fd00::2/128", size=9.5, color="#1565C0")
    txt(ax, 3.875, 4.3, "MTU 4096 · 全流量", size=7.5, color="#546E7A")

    # ---- Wi-Fi Router ----
    rbox(ax, 5.35, 4.15, 2.0, 1.6, "#FFF8E1", "#FFC107", radius=0.14)
    txt(ax, 6.35, 5.35, "Wi-Fi Router", size=11, color="#7A5900", weight="bold")
    txt(ax, 6.35, 4.85, "192.168.1.0/24", size=9, color="#A67C00")
    for dx, dy in [(-0.55, 0.35), (0.0, 0.45), (0.55, 0.35)]:
        ax.plot([6.35 + dx, 6.35 + dx], [5.9 + dy, 6.05 + dy], color="#FFC107",
                lw=1.5, zorder=6)
        ax.add_patch(Circle((6.35 + dx, 6.18 + dy), 0.03, fc="#FFC107",
                            ec="none", zorder=6))

    # ---- Server 手機 ----
    phone(ax, 8.35, 2.6, 1.95, 4.1, "5G Proxy Pro", C_ACCENT)
    txt(ax, 8.55, 5.45, "Port: 1080", size=7.5, ha="left")
    rbox(ax, 8.55, 4.95, 1.55, 0.3, "#DC3545", "#DC3545", radius=0.05)
    txt(ax, 9.325, 5.1, "Stop Proxy", size=7.5, color="white", weight="bold")
    txt(ax, 8.55, 4.35, "5G Proxy Running", size=7.5, color="#2E7D32",
        ha="left", weight="bold")
    txt(ax, 8.55, 3.9, "Wi-Fi Proxy:", size=7, ha="left")
    txt(ax, 8.55, 3.6, "192.168.1.178:1080", size=8, color=C_WIFI, ha="left",
        weight="bold")
    txt(ax, 8.35, 2.35, "Server 手機", size=10.5, color=C_SUB)
    txt(ax, 8.35, 2.05, "192.168.1.178:1080", size=9.5, color=C_WIFI,
        weight="bold")
    txt(ax, 8.35, 1.75, "5G SIM + Wi-Fi 同時開啟", size=8, color=C_5G)
    num_badge(ax, 10.75, 7.6, 2)

    # ---- 5G 基地台 ----
    ax.add_patch(Polygon([[10.35, 2.9], [10.85, 2.9], [10.6, 4.35]],
                         closed=True, facecolor="#B2DFDB", edgecolor="#00897B",
                         linewidth=1.5, zorder=2))
    ax.plot([10.6, 10.6], [4.35, 4.75], color="#00897B", lw=1.5, zorder=2)
    for i, r in enumerate([0.28, 0.5, 0.72]):
        ax.add_patch(Ellipse((10.6, 5.35), 2.2 * r, 0.75 * r, facecolor="none",
                             edgecolor="#00897B", lw=1.6, alpha=0.85,
                             zorder=2))
    txt(ax, 10.6, 6.45, "5G", size=12, color="#00695C", weight="bold")
    txt(ax, 10.6, 6.1, "基地台", size=9, color="#00695C")

    # ---- Internet 雲 ----
    for dx, dy, r in [(-0.85, -0.15, 0.55), (-0.4, 0.12, 0.62), (0.1, 0.0, 0.7),
                      (0.6, -0.1, 0.55), (-0.1, -0.45, 0.6)]:
        ax.add_patch(Circle((12.7 + dx, 5.9 + dy), r, facecolor="#ECEFF1",
                            edgecolor="#B0BEC5", lw=1.2, zorder=2))
    txt(ax, 12.7, 6.15, "Internet", size=12, color="#37474F", weight="bold")
    txt(ax, 12.7, 5.75, "網站 · DNS · QUIC", size=8.5, color="#546E7A")

    # ---- 流量箭頭 ----
    arrow(ax, 2.3, 5.5, 2.85, 5.25, color=C_ACCENT, lw=2.6)
    arrow(ax, 4.9, 5.0, 5.35, 5.0, color=C_ACCENT, lw=2.6)
    arrow(ax, 7.35, 5.0, 8.35, 5.0, color=C_ACCENT, lw=2.6)
    arrow(ax, 9.3, 4.75, 10.5, 3.6, color=C_5G, lw=2.6)
    arrow(ax, 11.4, 5.35, 11.85, 5.75, color="#607D8B", lw=2.0, ls="--")

    bb = dict(facecolor="white", alpha=0.85, edgecolor="none", pad=1.5)
    txt(ax, 2.6, 5.35, "App 全流量進 TUN", size=8.5, bbox=bb)
    txt(ax, 5.1, 5.4, "SOCKS5 連線（Wi-Fi 內網）", size=8.5, bbox=bb)
    txt(ax, 7.85, 5.4, "UDP-in-TCP 建議開啟", size=8.5, bbox=bb)
    txt(ax, 9.65, 3.15, "流量出口綁定 5G 介面\n(Network.bindSocket)", size=8.5,
        color=C_5G, bbox=bb)
    txt(ax, 11.62, 5.55, "出站", size=8, color="#607D8B", bbox=bb)

    # ---- 底部說明 ----
    for i, s in enumerate([
        "① 在 Server 手機（5G Proxy Pro）設定連接埠並啟動，記下「Wi-Fi 代理」的 IP:Port（本例 192.168.1.178:1080）",
        "② 在 Client 手機（5G Proxy Client）輸入 Server 的 IP 與 Port，點「啟動隧道」並允許 VPN",
        "③ 允許後 Client 所有 App 的流量即經 TUN → Wi-Fi → Server 手機 → 5G → Internet",
    ]):
        y = 1.35 - i * 0.55
        rbox(ax, 0.35, y - 0.26, 11.9, 0.52, "#E8F5E9", "#81C784",
             radius=0.07, lw=1.2, zorder=7)
        txt(ax, 0.5, y, s, size=10, color="#1B5E20", ha="left", zorder=8)

    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig1_architecture.png"),
                bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("OK ->", os.path.join(OUT, "fig1_architecture.png"))


if __name__ == "__main__":
    fig1()