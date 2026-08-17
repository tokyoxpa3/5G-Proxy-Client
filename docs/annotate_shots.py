# -*- coding: utf-8 -*-
"""
實機截圖加註工具 — 為 5G-Proxy-Client 圖文教學產生標註圖
執行：python docs/annotate_shots.py
輸出：docs/shots/*_annotated.png（右側加白邊註解欄）

換行規則：
  - 依「文字實際像素寬度」換行（CJK 為全寬、拉丁/數字為半寬）
  - 不切斷連續 token（IP:Port、網址、UDP-in-TCP 等）
  - emoji 以 Segoe UI Emoji 彩色字型繪製
"""
import os
import re
import unicodedata
from PIL import Image, ImageDraw, ImageFont

SHOTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shots")

FONT_B = r"C:\Windows\Fonts\msjhbd.ttc"   # 微軟正黑體粗體
FONT_R = r"C:\Windows\Fonts\msjh.ttc"     # 微軟正黑體
FONT_E = r"C:\Windows\Fonts\seguiemj.ttf"  # Segoe UI Emoji（彩色）
if not os.path.exists(FONT_B):
    FONT_B = r"C:\Windows\Fonts\simhei.ttf"
if not os.path.exists(FONT_R):
    FONT_R = r"C:\Windows\Fonts\simhei.ttf"

RED = (217, 83, 79)
WHITE = (255, 255, 255)
DARK = (33, 37, 41)
STRIP_BG = (250, 250, 250)

# token 化：CJK/全形字元一個一個；連續英數（含 . : / ( ) + - _）不切斷；
# 空白可斷行；其餘（含 emoji）單一字元
TOKEN_RE = re.compile(
    r"[\u3000-\u303f\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uff00-\uffef]"
    r"|[A-Za-z0-9][A-Za-z0-9_.:/()+\-]*"
    r"|\s"
    r"|."
)


def is_emoji(ch):
    cp = ord(ch)
    if 0x1F000 <= cp <= 0x1FAFF or cp in (0xFE0F, 0x200D):
        return True
    return unicodedata.category(ch) == "So"


def draw_mixed(d, xy, text, font, ef):
    """逐段繪製：emoji 用彩色 emoji 字型，其餘用中文字型"""
    x, y = xy
    seg = ""
    mode = None  # None=一般, 'e'=emoji
    for ch in text:
        m = "e" if is_emoji(ch) else None
        if m != mode and seg:
            f = ef if mode == "e" else font
            try:
                d.text((x, y), seg, font=f, fill=DARK, embedded_color=True)
            except Exception:
                d.text((x, y), seg, font=f, fill=DARK)
            x += f.getlength(seg)
            seg = ""
        mode = m
        seg += ch
    if seg:
        f = ef if mode == "e" else font
        try:
            d.text((x, y), seg, font=f, fill=DARK, embedded_color=True)
        except Exception:
            d.text((x, y), seg, font=f, fill=DARK)


def wrap_text(text, max_w, font, ef):
    """依像素寬度換行；token 不可被切斷；空格優先作為斷點"""
    tokens = TOKEN_RE.findall(text)
    lines, cur, cur_w = [], "", 0.0
    for tok in tokens:
        f = ef if (tok and is_emoji(tok[0])) else font
        w = f.getlength(tok)
        if tok.strip() == "":
            if cur and cur_w + w <= max_w:
                cur += tok
                cur_w += w
            continue
        if cur and cur_w + w > max_w:
            lines.append(cur.rstrip())
            cur = tok
            cur_w = w
        else:
            cur += tok
            cur_w += w
    if cur:
        lines.append(cur.rstrip())
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
    ef = ImageFont.truetype(FONT_E, 22)

    asc, desc = fr.getmetrics()
    line_h = asc + desc + 6
    pad = 12
    box_w = strip_w - 48

    if title:
        d.rectangle([iw, 0, iw + strip_w, ih], fill=(245, 245, 245))
        d.rectangle([iw + 24, 22, iw + strip_w - 24, 92], outline=RED, width=2)
        d.text((iw + 40, 38), title, font=fb, fill=RED)

    y = 120
    overflow = False
    for num, ix, iy, text in items:
        cx, cy = int(ix * scale), int(iy * scale)
        r = 22
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=RED, outline=WHITE, width=3)
        d.text((cx, cy), str(num), font=fb, fill=WHITE, anchor="mm")

        lines = wrap_text(text, box_w, fr, ef)
        bh = pad * 2 + line_h * len(lines)
        bx = iw + 24
        by = y
        if by + bh > ih - 10:
            overflow = True
            by = max(10, ih - bh - 10)
        d.rounded_rectangle([bx, by, bx + box_w, by + bh], radius=10,
                            fill=WHITE, outline=RED, width=2)
        ty = by + pad
        for ln in lines:
            draw_mixed(d, (bx + 16, ty), ln, fr, ef)
            ty += line_h
        # 折線箭頭：號碼圓 → 框左側
        sx, sy = bx, by + bh // 2
        d.line([cx + r + 4, cy, (sx + bx) // 2, cy, (sx + bx) // 2, sy, sx, sy],
               fill=RED, width=3)
        d.polygon([(sx, sy), (sx + 12, sy - 6), (sx + 12, sy + 6)], fill=RED)
        y += bh + 26

    canvas.save(dst)
    print(("OVERFLOW!" if overflow else "OK   "), os.path.basename(dst),
          canvas.size, "| lines:", [len(wrap_text(t, box_w, fr, ef)) for _, _, _, t in items])


def main():
    S = SHOTS

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

    annotate(
        os.path.join(S, "server_running.png"),
        os.path.join(S, "server_running_annotated.png"),
        [
            (1, 610, 593, "✅ 5G Proxy Running = 代理已運行"),
            (2, 610, 1497, "記下「Wi-Fi 代理」的 IP:Port → 192.168.1.178:1080（Client 要輸入這個）"),
            (3, 610, 1770, "「5G 行動 IP」= 49.215.85.39（驗證用：其他裝置出口 IP 應等於它）"),
            (4, 610, 1293, "停止代理請按「🛑 停止代理服務」"),
        ],
        title="Server 端：運行中，取得 IP:Port",
    )

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

    annotate(
        os.path.join(S, "client_vpn.png"),
        os.path.join(S, "client_vpn_annotated.png"),
        [
            (1, 360, 780, "第一次啟動會出現系統「連線要求」對話框"),
            (2, 506, 1396, "點「確定」允許 VPN（拒絕則無法建立隧道）"),
        ],
        title="Client 端：VPN 授權",
    )

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

    annotate(
        os.path.join(S, "client_notification.png"),
        os.path.join(S, "client_notification_annotated.png"),
        [
            (1, 360, 420, "通知列常駐「5G Proxy Client / Tunnel active」前景服務通知"),
        ],
        title="Client 端：前景服務通知",
    )

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