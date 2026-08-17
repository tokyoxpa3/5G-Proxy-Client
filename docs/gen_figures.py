# -*- coding: utf-8 -*-
"""
5G-Proxy-Client / 5G-Proxy-Pro 圖文教學 — 架構圖產生器 (優化版)
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
C_SUB = "#555555"


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


def num_badge(ax, x, y, n, r=0.24, size=12):
    ax.add_patch(Circle((x, y), r, facecolor=C_ACCENT, edgecolor="white",
                        linewidth=1.5, zorder=10))
    ax.text(x, y, str(n), color="white", ha="center", va="center",
            fontsize=size, fontweight="bold", zorder=11)


def phone(ax, x, y, w, h, title, accent):
    # 機身外框
    rbox(ax, x - 0.12, y - 0.12, w + 0.24, h + 0.24, "#1E1E1E", "#111111",
         radius=0.12, zorder=1)
    # 螢幕
    rbox(ax, x, y, w, h, "#FFFFFF", "#E0E0E0", radius=0.05, lw=1, zorder=2)
    # 頂部狀態列
    ax.add_patch(Rectangle((x, y + h - 0.32), w, 0.32, facecolor="#F0F0F0",
                           edgecolor="none", zorder=3))
    txt(ax, x + w - 0.15, y + h - 0.16, "10:24", size=6.5, color="#333", ha="right")
    txt(ax, x + 0.15, y + h - 0.16, "5G", size=6.5, color=C_5G, ha="left", weight="bold")
    txt(ax, x + w / 2, y + h - 0.72, title, size=11, weight="bold")
    return y + h - 0.95


def fig1():
    fig, ax = plt.subplots(figsize=(15.5, 8.5), dpi=150)
    ax.set_xlim(0, 15.5)
    ax.set_ylim(0, 8.5)
    ax.axis("off")
    ax.set_facecolor("#FAFAFA")

    # ---- 頂部大標題 ----
    rbox(ax, 0.5, 7.8, 14.5, 0.5, "#E8F0FE", C_WIFI, radius=0.08, lw=1)
    txt(ax, 7.75, 8.05, "5G Proxy 雙手機架構與網路流量轉發路徑", size=13, color=C_WIFI, weight="bold")

    # ---- 1. Client 手機 ----
    # x: 0.5 ~ 2.45, w: 1.95, center: 1.475
    cx1 = 1.475
    phone(ax, 0.5, 2.6, 1.95, 4.2, "5G Proxy Client", C_ACCENT)
    
    # 螢幕內容
    txt(ax, 0.7, 5.45, "SOCKS5 Server", size=7.5, ha="left")
    rbox(ax, 0.7, 5.0, 1.55, 0.28, "#E8F0FE", C_WIFI, radius=0.03, lw=1)
    txt(ax, 1.475, 5.14, "192.168.1.178", size=7.5, color=C_WIFI)
    rbox(ax, 0.7, 4.5, 1.55, 0.28, "#E8F0FE", C_WIFI, radius=0.03, lw=1)
    txt(ax, 1.475, 4.64, "1080", size=7.5, color=C_WIFI)
    rbox(ax, 0.7, 3.65, 1.55, 0.32, "#4CAF50", "#4CAF50", radius=0.05)
    txt(ax, 1.475, 3.81, "Start Tunnel", size=8, color="white", weight="bold")
    txt(ax, 0.7, 3.05, "Tunnel active", size=8, color="#2E7D32", ha="left", weight="bold")
    
    # 手機下方標籤 (置中於 cx1)
    txt(ax, cx1, 2.3, "Client 手機", size=10.5, color=C_SUB, weight="bold")
    txt(ax, cx1, 2.0, "Wi-Fi IP: 192.168.1.192", size=9.5, color=C_WIFI, weight="bold")
    num_badge(ax, 0.35, 7.0, 1)

    # ---- 2. TUN 虛擬網卡 ----
    # x: 2.95 ~ 4.85, w: 1.9, center: 3.9
    rbox(ax, 2.95, 4.15, 1.9, 1.8, "#E3F2FD", "#64B5F6", radius=0.12)
    txt(ax, 3.9, 5.5, "TUN 虛擬網卡", size=10.5, color="#0D47A1", weight="bold")
    txt(ax, 3.9, 5.05, "10.8.0.2 / 32", size=9.5, color="#1565C0")
    txt(ax, 3.9, 4.65, "fd00::2 / 128", size=9.5, color="#1565C0")
    txt(ax, 3.9, 4.3, "MTU 4096 · 全流量捕獲", size=7.5, color="#546E7A")

    # ---- 3. Wi-Fi Router ----
    # x: 5.35 ~ 7.15, w: 1.8, center: 6.25
    rbox(ax, 5.35, 4.15, 1.8, 1.8, "#FFF8E1", "#FFC107", radius=0.14)
    txt(ax, 6.25, 5.4, "Wi-Fi Router", size=11, color="#7A5900", weight="bold")
    txt(ax, 6.25, 4.9, "192.168.1.0 / 24", size=9, color="#A67C00")
    txt(ax, 6.25, 4.45, "(同區域網路)", size=8, color="#7A5900")
    # 天線
    for dx, dy in [(-0.45, 0.35), (0.0, 0.45), (0.45, 0.35)]:
        ax.plot([6.25 + dx, 6.25 + dx], [5.95 + dy, 6.1 + dy], color="#FFC107", lw=1.8, zorder=6)
        ax.add_patch(Circle((6.25 + dx, 6.22 + dy), 0.035, fc="#FFC107", ec="none", zorder=6))

    # ---- 4. Server 手機 ----
    # x: 7.65 ~ 9.60, w: 1.95, center: 8.625
    cx2 = 8.625
    phone(ax, 7.65, 2.6, 1.95, 4.2, "5G Proxy Pro", C_ACCENT)
    
    # 螢幕內容
    txt(ax, 7.85, 5.55, "Port: 1080", size=7.5, ha="left")
    rbox(ax, 7.85, 5.05, 1.55, 0.3, "#DC3545", "#DC3545", radius=0.05)
    txt(ax, 8.625, 5.2, "Stop Proxy", size=8, color="white", weight="bold")
    txt(ax, 7.85, 4.45, "5G Proxy Running", size=8, color="#2E7D32", ha="left", weight="bold")
    txt(ax, 7.85, 4.0, "Wi-Fi Proxy:", size=7, ha="left")
    txt(ax, 7.85, 3.7, "192.168.1.178:1080", size=8, color=C_WIFI, ha="left", weight="bold")
    
    # 手機下方標籤 (置中於 cx2)
    txt(ax, cx2, 2.3, "Server 手機", size=10.5, color=C_SUB, weight="bold")
    txt(ax, cx2, 2.0, "192.168.1.178:1080", size=9.5, color=C_WIFI, weight="bold")
    txt(ax, cx2, 1.75, "5G SIM + Wi-Fi 同時開啟", size=8, color=C_5G)
    num_badge(ax, 7.5, 7.0, 2)

    # ---- 5. 5G 基地台 ----
    # x: 10.9 ~ 12.1, center: 11.5
    cx3 = 11.5
    ax.add_patch(Polygon([[cx3 - 0.25, 2.9], [cx3 + 0.25, 2.9], [cx3, 4.35]],
                         closed=True, facecolor="#B2DFDB", edgecolor="#00897B",
                         linewidth=1.5, zorder=2))
    ax.plot([cx3, cx3], [4.35, 4.75], color="#00897B", lw=1.5, zorder=2)
    for r in [0.28, 0.48, 0.68]:
        ax.add_patch(Ellipse((cx3, 5.35), 2.0 * r, 0.7 * r, facecolor="none",
                             edgecolor="#00897B", lw=1.5, alpha=0.85, zorder=2))
    txt(ax, cx3, 6.35, "5G 基地台", size=10.5, color="#00695C", weight="bold")
    txt(ax, cx3, 6.0, "電信行動網路", size=8.5, color="#00695C")

    # ---- 6. Internet 雲端 ----
    # x: 13.0 ~ 15.0, center: 14.0
    cx4 = 14.0
    cy4 = 5.35
    for dx, dy, r in [(-0.65, -0.1, 0.45), (-0.3, 0.1, 0.52), (0.1, 0.0, 0.58),
                      (0.5, -0.08, 0.45), (-0.1, -0.35, 0.5)]:
        ax.add_patch(Circle((cx4 + dx, cy4 + dy), r, facecolor="#ECEFF1",
                            edgecolor="#B0BEC5", lw=1.2, zorder=2))
    txt(ax, cx4, cy4 + 0.12, "Internet", size=11.5, color="#37474F", weight="bold")
    txt(ax, cx4, cy4 - 0.22, "目標網站 / DNS", size=8.5, color="#546E7A")

    # ---- 流量路徑箭頭 ----
    # 1. Client -> TUN
    arrow(ax, 2.45, 5.05, 2.95, 5.05, color=C_ACCENT, lw=2.4)
    # 2. TUN -> Router
    arrow(ax, 4.85, 5.05, 5.35, 5.05, color=C_ACCENT, lw=2.4)
    # 3. Router -> Server
    arrow(ax, 7.15, 5.05, 7.65, 5.05, color=C_ACCENT, lw=2.4)
    # 4. Server -> 5G 基地台 (起點在 Server 右邊界 9.60)
    arrow(ax, 9.60, 4.35, 11.20, 3.65, color=C_5G, lw=2.4)
    # 5. 5G 基地台 -> Cloud
    arrow(ax, 11.85, 5.35, 13.35, 5.35, color="#607D8B", lw=2.0, ls="--")

    # 箭頭標籤
    bb = dict(facecolor="white", alpha=0.9, edgecolor="none", pad=1.5)
    txt(ax, 2.70, 5.45, "全流量進 TUN", size=8, color=C_ACCENT, bbox=bb)
    txt(ax, 5.10, 5.45, "SOCKS5 (Wi-Fi 內網)", size=8, color=C_ACCENT, bbox=bb)
    txt(ax, 7.40, 5.45, "UDP-in-TCP 轉發", size=8, color=C_ACCENT, bbox=bb)
    txt(ax, 10.40, 3.60, "出口綁定 5G 介面\n(Network.bindSocket)", size=8, color=C_5G, bbox=bb)
    txt(ax, 12.60, 5.65, "代理出站", size=8, color="#607D8B", bbox=bb)

    # ---- 底部說明卡片 (相距與高寬精確調整，完全不超出畫布) ----
    steps = [
        "① 在 Server 手機（5G Proxy Pro）設定連接埠（預設 1080）並啟動，記下「Wi-Fi 代理」IP:Port（本例 192.168.1.178:1080）",
        "② 在 Client 手機（5G Proxy Client）輸入 Server 的 IP 與 Port，勾選 UDP-in-TCP 後點「Start Tunnel」並允許 VPN",
        "③ 允許後 Client 所有 App 的流量即經 TUN 隧道 → Wi-Fi 內網 → Server 手機 → 5G 行動網路對外發出",
    ]
    for i, s in enumerate(steps):
        y_center = 1.25 - i * 0.45
        rbox(ax, 0.5, y_center - 0.18, 14.5, 0.38, "#E8F5E9", "#81C784", radius=0.06, lw=1.2, zorder=7)
        txt(ax, 0.7, y_center, s, size=9.5, color="#1B5E20", ha="left", zorder=8)

    fig.tight_layout()
    fig.savefig(os.path.join(OUT, "fig1_architecture.png"), bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print("OK ->", os.path.join(OUT, "fig1_architecture.png"))


if __name__ == "__main__":
    fig1()