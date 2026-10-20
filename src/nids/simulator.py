"""Имитационная модель потоков стенда провайдера (уровень записей NetFlow).

Генерирует записи потоков в единой схеме (см. features.FLOW_COLUMNS) для фонового трафика
абонентов и четырёх сценариев атак ТЗ: SYN-flood, UDP-flood, сканирование портов,
подбор пароля SSH. Параметры сценариев соответствуют инструментам стенда:
hping3 --flood (каждый пакет — новый поток с новым портом источника), nmap -sS -T4,
hydra -t 4. Журнал запусков возвращается вместе с потоками и служит разметкой.

Модель нужна, чтобы проверить онлайн-конвейер (задержку, ложные срабатывания,
производительность) до появления записей со стенда GNS3; она не заменяет стенд.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

ACK_PSH_FIN_SYN = 0x1B  # типичный набор флагов завершённой TCP-сессии
SYN, SYN_RST = 0x02, 0x06


@dataclass
class Scenario:
    kind: str          # SYN-flood | UDP-flood | Scan | Bruteforce
    start_s: float     # от начала записи
    dur_s: float
    rate: float        # потоков в секунду
    attacker: str = "198.51.100.66"
    target: str = "100.64.10.20"


class IspTrafficModel:
    """Абоненты 100.64.0.0/16 (за BNG), серверы ЦОД провайдера 10.0.0.0/24, внешние ресурсы."""

    def __init__(self, n_subscribers: int = 120, seed: int = 0):
        self.rng = np.random.default_rng(seed)
        r = self.rng
        self.subs = np.array([f"100.64.{i // 250}.{i % 250 + 2}" for i in range(n_subscribers)])
        self.ext = np.array([f"203.0.113.{i}" for i in range(1, 60)] +
                            [f"198.18.{i // 200}.{i % 200 + 1}" for i in range(400)])
        self.dns = np.array(["10.0.0.53", "10.0.0.54"])
        # интенсивность абонента: лог-нормальная, у части абонентов «тяжёлый» профиль
        self.activity = r.lognormal(mean=0.0, sigma=0.8, size=n_subscribers)

    # ------------------------------------------------------------ фон
    def background(self, dur_s: float, flows_per_sub_s: float = 0.6) -> pd.DataFrame:
        r = self.rng
        rate = self.activity * flows_per_sub_s
        n = r.poisson(rate * dur_s)
        src = np.repeat(self.subs, n)
        N = len(src)
        ts = r.uniform(0, dur_s, N)
        app = r.choice(5, size=N, p=[0.55, 0.25, 0.1, 0.07, 0.03])  # https,dns,http,quic,прочее
        dport = np.select([app == 0, app == 1, app == 2, app == 3],
                          [443, 53, 80, 443], default=r.choice([123, 993, 5222, 22, 8080], size=N))
        proto = np.where((app == 1) | (app == 3) | (dport == 123), 17, 6)
        dst = np.where(app == 1, r.choice(self.dns, N), r.choice(self.ext, N, p=self._zipf(len(self.ext))))
        pkts = np.where(app == 1, 2, np.maximum(3, r.lognormal(2.6, 1.2, N).astype(int)))
        bpp = np.where(app == 1, 90, r.uniform(200, 1200, N))
        dur = np.where(app == 1, r.uniform(0.001, 0.05, N), r.lognormal(0.5, 1.3, N))
        flags = np.where(proto == 6, ACK_PSH_FIN_SYN, 0)
        # небольшая доля неудачных TCP-подключений (только SYN) — реальный фон
        fail = (proto == 6) & (r.random(N) < 0.01)
        flags = np.where(fail, SYN, flags)
        pkts = np.where(fail, 1, pkts)
        dur = np.where(fail, 0.0, dur)
        return self._frame(ts, dur, src, dst, r.integers(1024, 65535, N), dport, proto,
                           (pkts * bpp).astype(int), pkts, flags, label=0, attack="Benign")

    def _zipf(self, n):
        w = 1 / np.arange(1, n + 1) ** 0.9
        return w / w.sum()

    # ------------------------------------------------------------ атаки
    def attack(self, sc: Scenario) -> pd.DataFrame:
        r = self.rng
        n = r.poisson(sc.rate * sc.dur_s)
        ts = sc.start_s + np.sort(r.uniform(0, sc.dur_s, n))
        sport = r.integers(1024, 65535, n)
        if sc.kind == "SYN-flood":    # hping3 -S -p 80 --flood
            return self._frame(ts, np.zeros(n), sc.attacker, sc.target, sport, 80, 6,
                               np.full(n, 60), np.ones(n, int), SYN, 1, sc.kind)
        if sc.kind == "UDP-flood":    # hping3 --udp -p 53 -d 512 --flood
            return self._frame(ts, np.zeros(n), sc.attacker, sc.target, sport, 53, 17,
                               np.full(n, 540), np.ones(n, int), 0, 1, sc.kind)
        if sc.kind == "Scan":         # nmap -sS -T4 -p- по нескольким хостам
            targets = np.array([sc.target] + list(r.choice(self.subs, 3)))
            dst = targets[(np.arange(n) // 1000) % len(targets)]
            dport = r.permutation(np.arange(1, 65536))[np.arange(n) % 65535]
            open_ = r.random(n) < 0.005
            return self._frame(ts, np.where(open_, 0.001, 0), sc.attacker, dst, sport, dport, 6,
                               np.where(open_, 104, 44), np.where(open_, 2, 1),
                               np.where(open_, SYN_RST, SYN), 1, sc.kind)
        if sc.kind == "Bruteforce":   # hydra -t 4 ssh://target
            pkts = r.integers(18, 30, n)
            return self._frame(ts, r.uniform(1.0, 3.5, n), sc.attacker, sc.target, sport, 22, 6,
                               pkts * r.integers(110, 160, n), pkts, ACK_PSH_FIN_SYN, 1, sc.kind)
        raise ValueError(sc.kind)

    def _frame(self, ts, dur, src, dst, sport, dport, proto, byts, pkts, flags, label, attack):
        n = len(ts)
        b = lambda v: np.broadcast_to(v, n)  # noqa: E731
        df = pd.DataFrame({"ts": (np.asarray(ts) * 1000).astype(np.int64), "src": b(src), "dst": b(dst),
                           "sport": b(sport), "dport": b(dport), "proto": b(proto), "bytes": b(byts),
                           "pkts": b(pkts), "flags": b(flags), "dur": b(dur).astype(float),
                           "label": label, "attack": attack})
        df["te"] = df["ts"] + (df["dur"] * 1000).astype(np.int64)
        return df

    def run(self, dur_s: float, scenarios: list[Scenario], t0_ms: int = 1_760_000_000_000,
            active_timeout_s: float = 60, inactive_timeout_s: float = 15) -> tuple[pd.DataFrame, pd.DataFrame]:
        """Возвращает (потоки в порядке экспорта, журнал атак).

        Время экспорта записи моделирует кэш потоков маршрутизатора: запись уходит в коллектор
        через inactive_timeout после последнего пакета, но не позже active_timeout от начала.
        """
        parts = [self.background(dur_s)] + [self.attack(s) for s in scenarios]
        f = pd.concat(parts, ignore_index=True)
        f["ts"] += t0_ms
        f["te"] += t0_ms
        f["export"] = np.minimum(f["te"] + int(inactive_timeout_s * 1000), f["ts"] + int(active_timeout_s * 1000))
        f = f.sort_values("export", kind="stable").reset_index(drop=True)
        journal = pd.DataFrame([{"kind": s.kind, "start": t0_ms + int(s.start_s * 1000),
                                 "end": t0_ms + int((s.start_s + s.dur_s) * 1000),
                                 "attacker": s.attacker, "target": s.target, "rate": s.rate} for s in scenarios])
        return f, journal


def default_scenarios(offset_s: float = 600, gap_s: float = 720, dur_s: float = 180,
                      intensity: float = 1.0) -> list[Scenario]:
    """Четыре сценария ТЗ, разнесённые во времени (как в журнале запусков стенда)."""
    kinds = [("SYN-flood", 1500), ("UDP-flood", 1500), ("Scan", 250), ("Bruteforce", 6)]
    return [Scenario(k, offset_s + i * gap_s, dur_s, rate * intensity) for i, (k, rate) in enumerate(kinds)]
