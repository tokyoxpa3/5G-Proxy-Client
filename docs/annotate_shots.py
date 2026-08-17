# -*- coding: utf-8 -*-
"""
實機截圖加註工具 — 為 5G-Proxy-Client 圖文教學產生標註圖
執行：python docs/annotate_shots.py
輸出：docs/shots/*_annotated.png（右側加白邊註解欄）
"""
import os
from PIL import Image, ImageDraw, ImageFont

SHOTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shots")

FONT_B = r"C:\Windows\Fonts\msjhbd.ttc"
FONT_R = r"C:\Windows\Fonts\msjh.ttc"
if not os.path.exists(FONT_B):
    FONT_B = r"C:\Windows\Fonts\simhei.ttf"
if not os.path.exists(FONT_R):
    FONT_R = r"C:\Windows\Fonts\simhei.ttf"

RED = (217, 83, 79)
RED_D = (183, 28, 28)
WHITE = (255, 255, 255)
DARK = (33, 37, 41)
STRIP_BG = (250, 250, 250)


def wrap_cn(text, n):
    lines, cur = [], ""
    for ch in text:
        cur += ch
        if len(cur) >= n and ch != " ":
            lines.append(cur)
            cur = ""
    if cur:
        lines.append(cur)
    return lines


def annotate(src, dst, items, scale_h=1350, strip_w=560, title=None):
    """items: list of (num, img_x, img_y, text)"""
    im = Image.open(src).convert("RGB")
    w, h = im.size
    scale = scale_h / h
    im = im.resize((int(w * scale), int(scale_h)), Image.LANCZOS)
    iw, ih = im.size

    canvas = Image.new("RGB", (iw + strip_w, ih), STRIP_BG)
    canvas.paste(im, (0, 0))

    d = ImageDraw.Draw(canvas)
    fb = ImageFont.truetype(FONT_B, 26)
    fr = ImageFont.truetype(FONT_R, 22)

    if title:
        d.rectangle([iw, 0, iw + strip_w, ih], fill=(245, 245, 245))
        d.rectangle([iw + 24, 22, iw + strip_w - 24, 92], outline=RED, width=2)
        d.text((iw + 40, 38), title, font=fb, fill=RED_D)

    y = 120
    for num, ix, iy, text in items:
        cx, cy = int(ix * scale), int(iy * scale)
        # 號碼圓
        r = 22
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=RED, outline=WHITE, width=3)
        d.text((cx, cy), str(num), font=fb, fill=WHITE, anchor="mm")
        # 說明框（右欄）
        lines = wrap_cn(text, 13)
        line_h = 30
        bw = strip_w - 48
        bh = 22 + line_h * len(lines)
        bx = iw + 24
        by = y
        d.rounded_rectangle([bx, by, bx + bw, by + bh], radius=10,
                            fill=WHITE, outline=RED, width=2)
        ty = by + 22
        for ln in lines:
            d.text((bx + 16, ty), ln, font=fr, fill=DARK)
            ty += line_h
        # 箭頭
        sx = bx
        sy = by + bh // 2
        # 折線：圓 → 框左側（分三段，避免穿過號碼）
        d.line([cx + r + 4, cy, (sx + bx) // 2, cy, (sx + bx) // 2, sy, sx, sy],
               fill=RED, width=3)
        d.polygon([(sx, sy), (sx + 12, sy - 6), (sx + 12, sy + 6)], fill=RED)
        y += bh + 26

    canvas.save(dst)
    print("OK ->", os.path.basename(dst), canvas.size)


def main():
    S = SHOTS

    # Server 初始（已停止）
    annotate(
        os.path.join(S, "server_initial.png"),
        os.path.join(S, "server_initial_annotated.png"),
        [
            (1, 735, 777, "檢查「代理端口」，改成要對外提供的埠（預設 1080）"),
            (2, 712, 946, "帳號密碼留空 = 開放代理；兩欄都填才會啟用認證"),
            (3, 610, 1299, "點「🚀 一鍵開啟 5G 代理」啟動服務"),
        ],
        title="Server 端：5G Proxy Pro 啟動",
    )

    # Server 運行中
    annotate(
        os.path.join(S, "server_running.png"),
        os.path.join(S, "server_running_annotated.png"),
        [
            (1, 610, 593, "✅ 5G Proxy Running = 代理已運行"),
            (2, 610, 1497, "記下「Wi-Fi 代理」的 IP:Port → 192.168.1.178:1080（Client 要輸入這個）"),
            (3, 610, 1770, "「5G 行動 IP」= 49.215.85.112（驗證用：其他裝置出口 IP 應等於它）"),
            (4, 610, 1293, "停止代理請按「🛑 停止代理服務」"),
        ],
        title="Server 端：運行中，取得 IP:Port",
    )

    # Client 填好表單
    annotate(
        os.path.join(S, "client_filled.png"),
        os.path.join(S, "client_filled_annotated.png"),
        [
            (1, 360, 335, "填 Server 的 IP：192.168.1.178"),
            (2, 360, 402, "填 Server 的連接埠：1080"),
            (3, 360, 610, "Server 端有設帳密才需要填（本教學兩端都留空）"),
            (4, 360, 677, "建議勾選「UDP relay 走 TCP」（與 5G Proxy Pro 的 UDP-in-TCP 搭配，DNS/QUIC 更穩）"),
            (5, 360, 748, "點「🚀 啟動隧道」開始"),
        ],
        title="Client 端：5G Proxy Client 設定",
    )

    # VPN 對話框
    annotate(
        os.path.join(S, "client_vpn.png"),
        os.path.join(S, "client_vpn_annotated.png"),
        [
            (1, 360, 780, "第一次啟動會出現系統「連線要求」對話框"),
            (2, 506, 1396, "點「確定」允許 VPN（拒絕則無法建立隧道）"),
        ],
        title="Client 端：VPN 授權",
    )

    # Client 運行中
    annotate(
        os.path.join(S, "client_running.png"),
        os.path.join(S, "client_running_annotated.png"),
        [
            (1, 360, 968, "「✅ 隧道已啟用 (192.168.1.178:1080)」= 成功"),
            (2, 360, 90, "狀態列出現鑰匙圖示（VPN 作用中）"),
            (3, 360, 824, "「🛑 停止隧道」可隨時關閉"),
        ],
        title="Client 端：隧道已啟用",
    )

    # Client 通知列
    annotate(
        os.path.join(S, "client_notification.png"),
        os.path.join(S, "client_notification_annotated.png"),
        [
            (1, 360, 420, "通知列常駐「5G Proxy Client / Tunnel active」前景服務通知"),
        ],
        title="Client 端：前景服務通知",
    )

    # Server 通知列
    annotate(
        os.path.join(S, "server_notification.png"),
        os.path.join(S, "server_notification_annotated.png"),
        [
            (1, 610, 420, "通知顯示「Locked 5G - Listening Port 1080」：已鎖定 5G 並監聽"),
        ],
        title="Server 端：前景服務通知",
    )


if __name__ == "__main__":
    main()