"""Схемы для пояснительной записки: архитектура, стенд, БД, конвейер (results/figures/diag_*.png)."""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

FIG = Path(__file__).resolve().parents[1] / "results" / "figures"
FIG.mkdir(parents=True, exist_ok=True)
plt.rcParams.update({"font.size": 10, "figure.dpi": 170, "savefig.bbox": "tight"})


def box(ax, x, y, w, h, text, fc="#ebf4ff", ec="#2b6cb0", fs=9, bold=False):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=fc, ec=ec, lw=1.3))
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center", fontsize=fs,
            fontweight="bold" if bold else "normal", wrap=True)


def arrow(ax, x1, y1, x2, y2, text=None, color="#2d3748", off=(0, 0.12)):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle="-|>", mutation_scale=12, lw=1.2, color=color))
    if text:
        ax.text((x1 + x2) / 2 + off[0], (y1 + y2) / 2 + off[1], text, ha="center", fontsize=8, color="#4a5568")


def canvas(w, h):
    fig, ax = plt.subplots(figsize=(w, h))
    ax.set_xlim(0, w); ax.set_ylim(0, h); ax.axis("off")
    return fig, ax


# ---------------------------------------------------------------- архитектура
fig, ax = canvas(11, 5.2)
box(ax, 0.2, 3.3, 2.2, 1.5, "Стенд провайдера\n(GNS3, MikroTik CHR)\nR-BORDER, R-CORE, R-BNG", "#f0fff4", "#2f855a")
box(ax, 3.0, 3.6, 1.8, 0.9, "Коллектор\nnfcapd (UDP 2055)", "#fffaf0", "#c05621")
box(ax, 5.3, 3.6, 1.8, 0.9, "Загрузчик\nnfdump → COPY", "#fffaf0", "#c05621")
box(ax, 7.6, 3.3, 2.0, 1.5, "PostgreSQL\nflows · windows ·\nincidents", "#faf5ff", "#6b46c1", bold=True)
box(ax, 3.0, 0.4, 5.6, 2.2, "", "#ebf8ff", "#2b6cb0")
ax.text(5.8, 2.38, "Детектор (онлайн-конвейер)", ha="center", fontsize=9.5, fontweight="bold")
box(ax, 3.2, 1.35, 1.25, 0.75, "Окна 10 с,\nпризнаки", fs=8)
box(ax, 4.75, 1.62, 1.6, 0.5, "Пороговые правила", fs=8)
box(ax, 4.75, 1.05, 1.6, 0.5, "Isolation Forest", fs=8)
box(ax, 4.75, 0.48, 1.6, 0.5, "XGBoost (тип)", fs=8)
box(ax, 6.7, 0.9, 1.7, 0.8, "Формирование\nинцидентов", fs=8)
for y in (1.87, 1.3, 0.73):
    arrow(ax, 4.45, 1.72, 4.75, y)
    arrow(ax, 6.35, y, 6.7, 1.3)
box(ax, 9.1, 1.7, 1.7, 0.8, "Telegram Bot API", "#fff5f5", "#c53030")
box(ax, 9.1, 0.4, 1.7, 0.8, "Grafana\n(дашборд)", "#fff5f5", "#c53030")
ax.text(2.7, 4.65, "NetFlow v9 /\nIPFIX", ha="center", fontsize=8, color="#4a5568")
arrow(ax, 2.4, 4.05, 3.0, 4.05)
arrow(ax, 4.8, 4.05, 5.3, 4.05, "файлы", off=(0, 0.15))
arrow(ax, 7.1, 4.05, 7.6, 4.05, "COPY", off=(0, 0.15))
arrow(ax, 7.9, 3.3, 3.85, 2.12, "новые потоки (опрос 5 с)", off=(0.4, 0.15))
arrow(ax, 8.0, 1.7, 8.6, 3.3, "окна,\nинциденты", off=(-0.55, 0.1))
arrow(ax, 8.4, 1.3, 9.1, 2.05, "оповещение", off=(0.45, -0.35))
arrow(ax, 9.3, 3.3, 9.95, 1.2, "SQL", off=(0.3, 0.0))
ax.set_title("Архитектура прототипа системы обнаружения аномалий", fontsize=11)
fig.savefig(FIG / "diag_architecture.png"); plt.close(fig)

# ---------------------------------------------------------------- стенд
fig, ax = canvas(10, 6.4)
G, R, H, C = ("#f0fff4", "#2f855a"), ("#ebf4ff", "#2b6cb0"), ("#fffaf0", "#c05621"), ("#faf5ff", "#6b46c1")
box(ax, 1.0, 5.2, 2.4, 0.8, "EXT-SRV\n203.0.113.10", *H)
box(ax, 6.6, 5.2, 2.4, 0.8, "ATTACKER\n198.51.100.66\nhping3, nmap, hydra", "#fff5f5", "#c53030", fs=8)
box(ax, 3.6, 3.8, 2.8, 0.9, "R-BORDER (CHR)\nlo 10.255.0.1 · NetFlow v9", *R, bold=True)
box(ax, 3.6, 2.3, 2.8, 0.9, "R-CORE (CHR)\nlo 10.255.0.2 · OSPF", *R, bold=True)
box(ax, 7.2, 2.35, 2.5, 0.8, "ISP-SRV DNS/WEB 10.0.0.53\nКоллектор 10.0.0.100", *C, fs=8)
box(ax, 3.6, 0.8, 2.8, 0.9, "R-BNG (CHR)\nlo 10.255.0.3 · NetFlow v9", *R, bold=True)
box(ax, 0.3, 0.1, 2.4, 0.8, "SUB-1\n100.64.10.20", *G)
box(ax, 7.3, 0.1, 2.4, 0.8, "SUB-2\n100.64.10.21", *G)
arrow(ax, 2.2, 5.2, 4.0, 4.7, "203.0.113.0/24", off=(-0.6, 0))
arrow(ax, 7.8, 5.2, 6.0, 4.7, "198.51.100.0/24", off=(0.6, 0))
arrow(ax, 5.0, 3.8, 5.0, 3.2, "10.0.12.0/30", off=(0.75, 0))
arrow(ax, 6.4, 2.75, 7.2, 2.75, "10.0.0.0/24", off=(0, 0.12))
arrow(ax, 5.0, 2.3, 5.0, 1.7, "10.0.23.0/30", off=(0.75, 0))
arrow(ax, 3.6, 1.1, 1.8, 0.9, "100.64.10.0/24", off=(-0.3, 0.15))
arrow(ax, 6.4, 1.1, 8.3, 0.9)
ax.annotate("", xy=(8.2, 3.15), xytext=(6.4, 4.2), arrowprops=dict(arrowstyle="-|>", ls="--", color="#6b46c1"))
ax.annotate("", xy=(8.0, 2.35), xytext=(6.4, 1.4), arrowprops=dict(arrowstyle="-|>", ls="--", color="#6b46c1"))
ax.text(7.6, 3.85, "экспорт потоков\nUDP 2055", fontsize=8, color="#6b46c1")
ax.set_title("Топология стенда упрощённой сети провайдера", fontsize=11)
fig.savefig(FIG / "diag_stand.png"); plt.close(fig)

# ---------------------------------------------------------------- схема БД
fig, ax = canvas(10, 4.4)
tables = [("flows", ["id BIGSERIAL PK", "exporter INET", "ts, te TIMESTAMPTZ", "src, dst INET", "sport, dport INT",
                     "proto SMALLINT", "bytes, pkts BIGINT", "flags SMALLINT", "received_at"]),
          ("windows", ["win_start TIMESTAMPTZ PK", "src INET PK", "flows, pkts_s, bytes_s", "uniq_dst_ip/port",
                       "syn_only_ratio", "ent_dst_ip/port", "mean_dur", "rules_type, if_score", "xgb_type, xgb_conf"]),
          ("incidents", ["id BIGSERIAL PK", "started_at, updated_at", "src, dst INET", "kind TEXT",
                         "confidence REAL", "detectors TEXT[]", "windows INT", "notified BOOL", "created_at"])]
for i, (name, cols) in enumerate(tables):
    x = 0.3 + i * 3.3
    ax.add_patch(FancyBboxPatch((x, 0.2), 2.9, 3.6, boxstyle="round,pad=0.02", fc="#ffffff", ec="#4a5568"))
    ax.add_patch(FancyBboxPatch((x, 3.35), 2.9, 0.45, boxstyle="round,pad=0.02", fc="#2b6cb0", ec="#2b6cb0"))
    ax.text(x + 1.45, 3.57, name, ha="center", va="center", color="white", fontweight="bold")
    for j, c in enumerate(cols):
        ax.text(x + 0.12, 3.05 - j * 0.31, c, fontsize=8.5, family="monospace")
arrow(ax, 3.2, 2.0, 3.6, 2.0, "агрегация", off=(0, 0.15))
arrow(ax, 6.5, 2.0, 6.9, 2.0, "детекторы", off=(0, 0.15))
ax.set_title("Схема базы данных прототипа", fontsize=11)
fig.savefig(FIG / "diag_db.png"); plt.close(fig)

# ---------------------------------------------------------------- временная диаграмма задержки
fig, ax = canvas(10, 2.6)
ax.plot([0.5, 9.5], [1.2, 1.2], color="#2d3748", lw=1)
marks = [(0.8, "t₀ начало\nатаки"), (2.4, "закрытие окна\n(W = 10 с)"), (5.6, "экспорт записи\n(inactive 15 с)"),
         (7.2, "закрытие окна\nв конвейере\n(+grace 20 с)"), (8.6, "оповещение\n(шаг опроса 5 с)")]
for x, t in marks:
    ax.plot([x, x], [1.05, 1.35], color="#c53030", lw=1.5)
    ax.text(x, 1.5, t, ha="center", va="bottom", fontsize=8)
ax.annotate("", xy=(8.6, 0.75), xytext=(0.8, 0.75), arrowprops=dict(arrowstyle="<->", color="#2b6cb0"))
ax.text(4.7, 0.45, "задержка обнаружения ≈ W + grace + шаг опроса ≤ 35–40 с", ha="center", color="#2b6cb0")
ax.set_title("Составляющие задержки обнаружения", fontsize=11)
fig.savefig(FIG / "diag_latency.png"); plt.close(fig)
print("ok")

# ---------------------------------------------------------------- иерархия сети провайдера
fig, ax = canvas(10.5, 5.6)
box(ax, 0.3, 4.6, 2.2, 0.7, "Вышестоящие\nоператоры / IX", "#f7fafc", "#4a5568")
box(ax, 8.0, 4.6, 2.2, 0.7, "Интернет\n(источник атак)", "#fff5f5", "#c53030")
box(ax, 3.6, 4.4, 3.2, 0.9, "Пограничные маршрутизаторы\n(BGP) · экспорт NetFlow/IPFIX", "#ebf4ff", "#2b6cb0", bold=True)
box(ax, 3.6, 3.0, 3.2, 0.9, "Ядро сети (MPLS/IP)", "#ebf4ff", "#2b6cb0", bold=True)
box(ax, 7.5, 3.05, 2.7, 0.8, "ЦОД провайдера:\nDNS, биллинг, RADIUS", "#faf5ff", "#6b46c1", fs=8)
box(ax, 0.3, 3.05, 2.7, 0.8, "Коллектор потоков\nи система обнаружения", "#f0fff4", "#2f855a", fs=8, bold=True)
box(ax, 1.4, 1.6, 3.0, 0.9, "BNG/BRAS: PPPoE/IPoE,\nCGNAT · экспорт NetFlow", "#ebf4ff", "#2b6cb0", fs=8.5)
box(ax, 6.0, 1.6, 3.0, 0.9, "BNG/BRAS (узел 2)", "#ebf4ff", "#2b6cb0", fs=8.5)
for x in (0.6, 2.1, 3.6, 6.2, 7.7):
    box(ax, x, 0.2, 1.3, 0.7, "OLT / коммут.\nдоступа", "#fffaf0", "#c05621", fs=7.5)
ax.text(10.3, 0.5, "уровень доступа", ha="right", fontsize=8, color="#4a5568")
ax.text(10.3, 2.0, "уровень агрегации", ha="right", fontsize=8, color="#4a5568")
arrow(ax, 2.5, 4.95, 3.6, 4.85); arrow(ax, 8.0, 4.95, 6.8, 4.85)
arrow(ax, 5.2, 4.4, 5.2, 3.9); arrow(ax, 6.8, 3.45, 7.5, 3.45)
arrow(ax, 4.6, 3.0, 2.9, 2.5); arrow(ax, 5.8, 3.0, 7.5, 2.5)
for x in (1.25, 2.75, 4.25):
    arrow(ax, 2.9, 1.6, x, 0.9)
for x in (6.85, 8.35):
    arrow(ax, 7.5, 1.6, x, 0.9)
ax.annotate("", xy=(1.7, 3.85), xytext=(3.6, 4.6), arrowprops=dict(arrowstyle="-|>", ls="--", color="#2f855a"))
ax.annotate("", xy=(1.6, 3.05), xytext=(2.2, 2.5), arrowprops=dict(arrowstyle="-|>", ls="--", color="#2f855a"))
ax.text(1.5, 4.25, "NetFlow / IPFIX", fontsize=8, color="#2f855a")
ax.set_title("Иерархическая архитектура сети провайдера", fontsize=11)
fig.savefig(FIG / "diag_isp.png"); plt.close(fig)
print("isp ok")

# ---------------------------------------------------------------- диаграмма последовательности
fig, ax = canvas(11, 6.2)
actors = ["Маршрутизатор", "nfcapd", "loader", "PostgreSQL", "detector", "Telegram", "Grafana"]
xs = [0.8 + i * 1.55 for i in range(len(actors))]
for x, a in zip(xs, actors):
    box(ax, x - 0.7, 5.5, 1.4, 0.5, a, fs=8.5)
    ax.plot([x, x], [0.2, 5.5], color="#a0aec0", ls="--", lw=0.8)
msgs = [(0, 1, 5.1, "NetFlow v9 / IPFIX (UDP)"), (1, 1, 4.7, "ротация файла каждые 10 с"),
        (2, 1, 4.3, "nfdump -r файл -o csv"), (2, 3, 3.9, "COPY flows"),
        (4, 3, 3.5, "SELECT ... WHERE id > last_id"), (4, 4, 3.1, "окна → признаки → 3 детектора"),
        (4, 3, 2.7, "INSERT windows, incidents"), (4, 5, 2.3, "sendMessage (инцидент)"),
        (6, 3, 1.6, "SQL-запросы панелей (каждые 10 с)"), (3, 6, 1.2, "трафик, журнал инцидентов")]
for a, b, y, txt in msgs:
    if a == b:
        ax.annotate("", xy=(xs[a] + 0.05, y - 0.2), xytext=(xs[a] + 0.05, y),
                    arrowprops=dict(arrowstyle="-|>", connectionstyle="arc3,rad=-1.2", color="#2d3748"))
        ax.text(xs[a] + 0.35, y - 0.1, txt, fontsize=8, va="center")
    else:
        ax.annotate("", xy=(xs[b], y), xytext=(xs[a], y), arrowprops=dict(arrowstyle="-|>", color="#2d3748"))
        ax.text((xs[a] + xs[b]) / 2, y + 0.07, txt, fontsize=8, ha="center")
ax.add_patch(FancyBboxPatch((xs[4] - 0.15, 2.15), 0.3, 1.55, boxstyle="square,pad=0", fc="#ebf4ff", ec="#2b6cb0"))
ax.text(xs[4] + 0.2, 1.95, "цикл каждые 5 с", fontsize=8, color="#2b6cb0")
ax.set_title("Диаграмма последовательности обработки потоков", fontsize=11)
fig.savefig(FIG / "diag_sequence.png"); plt.close(fig)
print("seq ok")
