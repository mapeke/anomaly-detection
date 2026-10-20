"""Оповещения об инцидентах (ФТ-4): Telegram Bot API и журнал."""
from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

import requests

from .engine import Incident

log = logging.getLogger("nids.alerts")
KIND_RU = {"SYN-flood": "SYN-флуд", "UDP-flood": "UDP-флуд", "Scan": "Сканирование портов",
           "Bruteforce": "Подбор пароля", "Volumetric": "Объёмная атака", "Anomaly": "Аномалия трафика"}


def format_incident(inc: Incident) -> str:
    t = datetime.fromtimestamp(inc.start_ms / 1000, tz=timezone.utc).astimezone()
    return (f"🚨 <b>{KIND_RU.get(inc.kind, inc.kind)}</b>\n"
            f"Время: {t:%Y-%m-%d %H:%M:%S}\n"
            f"Источник: <code>{inc.src}</code>\n"
            f"Цель: <code>{inc.dst}</code>\n"
            f"Уверенность: {inc.confidence:.0%}\n"
            f"Детекторы: {', '.join(inc.detectors)}")


class TelegramNotifier:
    def __init__(self, token: str | None = None, chat_id: str | None = None):
        self.token = token or os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID", "")

    @property
    def enabled(self) -> bool:
        return bool(self.token and self.chat_id)

    def send(self, inc: Incident) -> bool:
        text = format_incident(inc)
        log.warning("INCIDENT %s", text.replace("\n", " | "))
        if not self.enabled:
            return False
        try:
            r = requests.post(f"https://api.telegram.org/bot{self.token}/sendMessage",
                              json={"chat_id": self.chat_id, "text": text, "parse_mode": "HTML"}, timeout=5)
            r.raise_for_status()
            return True
        except requests.RequestException as e:
            log.error("telegram: %s", e)
            return False
