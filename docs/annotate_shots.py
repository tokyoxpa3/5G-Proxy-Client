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
    x, y = xy
    seg = ""
    mode = None
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
        sx, sy = bx, by + bh // 2
        d.line([cx + r + 4, cy, (sx + bx) // 2, cy, (sx + bx) // 2, sy, sx, sy],
               fill=RED, width=3)
        d.polygon([(sx, sy), (sx + 12, sy - 6), (sx + 12, sy + 6)], fill=RED)
        y += bh + 26

    canvas.save(dst)
    print(("OVERFLOW!" if overflow else "OK   "), os.path.basename(dst),
          canvas.size)


def main():
    S = SHOTS

    # --- Server 端 ---

    annotate(
        os.path.join(S, "server_initial.png"),
        os.path.join(S, "server_initial_annotated.png"),
        [
            (1, 735, 777, "代理端口（預設 1080）"),
            (2, 706, 956, "使用者/密碼留空 = 開放代理；兩欄都填才啟用認證"),
            (3, 610, 1299, "點「🚀 一鍵開啟 5G 代理」"),
            (4, 610, 2075, "新增「📈 流量」即時統計（上/下傳速率與總量）"),
        ],
        title="Server 端：5G Proxy Pro 啟動",
    )

    annotate(
        os.path.join(S, "server_battery.png"),
        os.path.join(S, "server_battery_annotated.png"),
        [
            (1, 609, 926, "小米/POCO 用戶的電池最佳化提醒"),
            (2, 253, 1748, "「仍然繼續」= 不加白名單也照樣啟動"),
            (3, 966, 1748, "「前往設定」= 關閉「5G 智慧省電」以穩定鎖定 5G"),
        ],
        title="Server 端：電池最佳化提醒",
    )

    annotate(
        os.path.join(S, "server_notifperm.png"),
        os.path.join(S, "server_notifperm_annotated.png"),
        [
            (1, 609, 1894, "Android 13+ 首次啟動會要求通知權限"),
            (2, 609, 2164, "點「允許」前景服務通知才能顯示"),
        ],
        title="Server 端：通知權限",
    )

    annotate(
        os.path.join(S, "server_running.png"),
        os.path.join(S, "server_running_annotated.png"),
        [
            (1, 610, 593, "✅ 5G Proxy Running = 代理已運行"),
            (2, 610, 1624, "記下「Wi-Fi 代理」IP:Port → 192.168.1.178:1080"),
            (3, 610, 1897, "「5G 行動 IP」= 出口 IP（其他裝置走代理後應等於它）"),
            (4, 610, 2069, "即時流量統計（上/下傳速率與總量）"),
            (5, 610, 1293, "「🛑 停止代理服務」關閉"),
        ],
        title="Server 端：運行中，取得 IP:Port",
    )

    annotate(
        os.path.join(S, "server_notification.png"),
        os.path.join(S, "server_notification_annotated.png"),
        [
            (1, 603, 977, "「已鎖定 5G - 監聽 Port 1080」= 已鎖定 5G 並監聽"),
        ],
        title="Server 端：前景服務通知",
    )

    # --- Client 端 ---

    annotate(
        os.path.join(S, "client_notifperm.png"),
        os.path.join(S, "client_notifperm_annotated.png"),
        [
            (1, 360, 1195, "Android 13+ 首次啟動要求通知權限"),
            (2, 360, 1284, "點「允許」"),
        ],
        title="Client 端：通知權限",
    )

    annotate(
        os.path.join(S, "client_filled.png"),
        os.path.join(S, "client_filled_annotated.png"),
        [
            (1, 360, 299, "伺服器 IP：192.168.1.178"),
            (2, 360, 366, "連接埠：1080"),
            (3, 360, 707, "認證留空（開放代理）"),
            (4, 360, 1321, "建議勾選「UDP relay 走 TCP」"),
            (5, 360, 1385, "「Remote DNS」由伺服器端解析"),
            (6, 360, 1181, "點「🚀 啟動隧道」"),
        ],
        title="Client 端：5G Proxy Client 設定",
    )

    annotate(
        os.path.join(S, "client_vpn.png"),
        os.path.join(S, "client_vpn_annotated.png"),
        [
            (1, 360, 980, "首次啟動出現系統「連線要求」"),
            (2, 506, 1396, "點「確定」允許 VPN"),
        ],
        title="Client 端：VPN 授權",
    )

    annotate(
        os.path.join(S, "client_running.png"),
        os.path.join(S, "client_running_annotated.png"),
        [
            (1, 360, 1181, "按鈕變為「🛑 停止隧道」= 隧道已啟用"),
            (2, 360, 1321, "執行中設定欄位鎖定"),
        ],
        title="Client 端：隧道已啟用",
    )


if __name__ == "__main__":
    main()
