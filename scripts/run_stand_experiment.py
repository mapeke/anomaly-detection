"""Полный эксперимент на Docker-стенде (stand/lab): запись трафика, переобучение, оценка НФТ-2.

  1) норма 60 мин (фон на SUB-1 и SUB-2)                          — обучение правил и Isolation Forest
  2) обучающие атаки ~40 мин: 4 сценария полной и пониженной интенсивности на фоне — обучение XGBoost
  3) переобучение (train_stand.py), перезапуск детектора с новыми моделями
  4) тестовый час: фон + 4 атаки по 3 мин с паузами 9 мин        — НФТ-2, детектор работает онлайн
  5) час чистого фона                                             — ложные оповещения
  6) оценка (eval_stand.py) -> results/stand_eval_*.json

Стенд должен быть запущен:
  docker compose -p nidslab -f docker-compose.yml -f stand/lab/docker-compose.lab.yml up -d --build
Запуск: python scripts/run_stand_experiment.py   (≈ 3 ч 45 мин; журнал — results/stand_session.log)
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
P = "nidslab"
COMPOSE = ["docker", "compose", "-p", P, "-f", "docker-compose.yml", "-f", "stand/lab/docker-compose.lab.yml"]
LOG = ROOT / "results" / "stand_session.log"
SESSION = ROOT / "stand" / "journals" / "session.json"
FULL = {"RATE": "-i u500", "NMAP": "-T4 --max-rate 300"}           # 2000 пакетов/с, 300 портов/с
LOW = {"MODE": "low", "RATE": "-i u2000", "NMAP": "-T3 --max-rate 60"}
session: dict = {}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def log(msg: str):
    line = f"{now()} UTC  {msg}"
    print(line, flush=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def mark(key: str):
    session[key] = now()
    SESSION.write_text(json.dumps(session, indent=2), encoding="utf-8")
    log(f"mark {key} = {session[key]}")


def sh(args, check=True, **kw):
    return subprocess.run(args, cwd=ROOT, check=check, capture_output=True, text=True, encoding="utf-8", **kw)


def exec_(container: str, cmd: str, env: dict | None = None, detach=False):
    e = sum((["-e", f"{k}={v}"] for k, v in (env or {}).items()), [])
    return sh(["docker", "exec", *(["-d"] if detach else []), *e, f"{P}-{container}-1", "bash", "-c", cmd])


def background(seconds: int):
    for h in ("sub-1", "sub-2"):
        exec_(h, f"cd /opt/stand && DUR={seconds} ./background.sh >/dev/null 2>&1", detach=True)
    log(f"фон запущен на SUB-1, SUB-2 на {seconds} с")


def attacks(journal: str, dur: int, pause: int, env: dict):
    env = {**env, "DUR": str(dur), "PAUSE": str(pause), "JOURNAL": journal}
    log(f"атаки -> {journal}: {env}")
    r = exec_("attacker", "cd /opt/stand && ./run_attacks.sh", env=env)
    log(r.stdout.strip().replace("\n", " | ")[-600:])
    text = exec_("attacker", f"cat /opt/stand/{journal}").stdout
    (ROOT / "stand" / "journals" / journal).write_text(text, encoding="utf-8")


def wait_until(t_end: float):
    while time.time() < t_end:
        time.sleep(min(30, max(0.0, t_end - time.time())))


def main():
    LOG.parent.mkdir(exist_ok=True)
    SESSION.parent.mkdir(exist_ok=True)
    for j in ("train_full.csv", "train_low.csv", "test.csv"):
        exec_("attacker", f"rm -f /opt/stand/{j}")
    sh(["docker", "exec", f"{P}-db-1", "psql", "-U", "nids", "-q", "-c",
        "truncate flows, windows, incidents restart identity;"])
    log("таблицы очищены, начало эксперимента")

    # 1) норма
    mark("normal_start")
    t = time.time()
    background(3600)
    wait_until(t + 3600 + 30)
    mark("normal_end")

    # 2) обучающие атаки
    mark("train_start")
    background(2700)
    time.sleep(60)
    attacks("train_full.csv", 120, 180, FULL)
    attacks("train_low.csv", 120, 180, LOW)
    mark("train_end")

    # 3) переобучение
    r = sh([sys.executable, "scripts/train_stand.py", "--normal", session["normal_start"], session["normal_end"],
            "--attacks", session["train_start"], session["train_end"],
            "--journal", "stand/journals/train_full.csv", "stand/journals/train_low.csv"], check=False)
    log("train_stand: " + (r.stdout + r.stderr).strip().replace("\n", " | ")[-1500:])
    if r.returncode != 0:
        sys.exit("обучение не удалось")
    sh([*COMPOSE, "restart", "detector"])
    log("детектор перезапущен с моделями стенда")
    time.sleep(30)

    # 4) тестовый час
    mark("test_start")
    t = time.time()
    background(3600)
    time.sleep(180)
    attacks("test.csv", 180, 540, FULL)
    wait_until(t + 3600)
    mark("test_end")
    time.sleep(60)  # дождаться закрытия последних окон

    # 5) час чистого фона
    mark("bg_start")
    t = time.time()
    background(3600)
    wait_until(t + 3600)
    mark("bg_end")
    time.sleep(60)

    # 6) оценка
    (ROOT / "stand" / "journals" / "empty.csv").write_text("kind,start,end,attacker,target\n", encoding="utf-8")
    for args, out in (((session["test_start"], session["test_end"]), "stand_eval_test.json"),
                      ((session["bg_start"], session["bg_end"]), "stand_eval_background.json")):
        jr = "stand/journals/test.csv" if "test" in out else "stand/journals/empty.csv"
        r = sh([sys.executable, "scripts/eval_stand.py", "--period", *args, "--journal", jr,
                "--out", f"results/{out}"], check=False)
        log(f"{out}: " + (r.stdout + r.stderr).strip().replace("\n", " | "))
    r = sh([sys.executable, "scripts/eval_stand.py", "--period", session["test_start"], session["test_end"],
            "--journal", "stand/journals/test.csv", "--offline", "--out", "results/stand_eval_test_offline.json"],
           check=False)
    log("offline: " + (r.stdout + r.stderr).strip().replace("\n", " | "))
    log("эксперимент завершён")


if __name__ == "__main__":
    main()
