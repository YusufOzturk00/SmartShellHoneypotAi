import requests
import os
import json
import time
import threading
from queue import Queue

alert_queue = Queue()
ALERT_COOLDOWN = {}
COOLDOWN_SECONDS = 60


def send_alert(alert_type: str, data: dict):
    """Alert kuyruğuna ekle (non-blocking)"""
    key = f"{alert_type}:{data.get('ip', 'unknown')}"

    # Cooldown kontrolü (spam önleme)
    last_sent = ALERT_COOLDOWN.get(key, 0)
    if time.time() - last_sent < COOLDOWN_SECONDS:
        return

    ALERT_COOLDOWN[key] = time.time()
    alert_queue.put({"type": alert_type, "data": data, "timestamp": time.time()})


def _process_alerts():
    """Arka planda alert gönder"""
    while True:
        try:
            alert = alert_queue.get(timeout=5)
        except:
            continue

        # Slack / Discord webhook
        webhook_url = os.environ.get("ALERT_WEBHOOK")
        if webhook_url:
            _send_webhook(webhook_url, alert)

        # Telegram
        tg_token = os.environ.get("ALERT_TELEGRAM_TOKEN")
        tg_chat = os.environ.get("ALERT_TELEGRAM_CHAT")
        if tg_token and tg_chat:
            _send_telegram(tg_token, tg_chat, alert)


def _send_webhook(url: str, alert: dict):
    try:
        severity_emoji = {"INFO": "ℹ️", "WARNING": "⚠️", "ALERT": "🚨", "CRITICAL": "🔴"}
        atype = alert["type"]
        data = alert["data"]

        message = {
            "content": f"{severity_emoji.get(atype, '📢')} **Honeypot {atype}**\n"
                       f"```json\n{json.dumps(data, indent=2, default=str)[:1500]}\n```",
        }

        # Slack format
        if "hooks.slack.com" in url:
            message = {
                "text": f"{severity_emoji.get(atype, '📢')} Honeypot {atype}",
                "blocks": [{
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"```{json.dumps(data, indent=2, default=str)[:2500]}```"}
                }]
            }

        requests.post(url, json=message, timeout=5)
    except:
        pass


def _send_telegram(token: str, chat_id: str, alert: dict):
    try:
        severity_emoji = {"INFO": "ℹ️", "WARNING": "⚠️", "ALERT": "🚨", "CRITICAL": "🔴"}
        atype = alert["type"]
        data = alert["data"]

        text = (
            f"{severity_emoji.get(atype, '📢')} <b>Honeypot {atype}</b>\n\n"
            f"<pre>{json.dumps(data, indent=2, default=str)[:3500]}</pre>"
        )

        requests.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML"},
            timeout=5,
        )
    except:
        pass


# Alert worker thread başlat
_worker = threading.Thread(target=_process_alerts, daemon=True)
_worker.start()