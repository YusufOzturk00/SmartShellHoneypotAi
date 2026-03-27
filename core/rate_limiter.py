import time
import threading

_connections = {}
_banned_ips = {}
_lock = threading.Lock()

MAX_CONNECTIONS_PER_IP = 5
BAN_THRESHOLD = 15          # 15 bağlantı denemesi
BAN_DURATION = 3600         # 1 saat ban
TIME_WINDOW = 300           # 5 dakika pencere


def check_rate_limit(ip: str) -> dict:
    """IP'nin bağlanmasına izin ver veya engelle"""
    now = time.time()

    with _lock:
        # Ban kontrolü
        ban_until = _banned_ips.get(ip, 0)
        if now < ban_until:
            return {
                "allowed": False,
                "reason": "IP banned",
                "ban_remaining": round(ban_until - now),
            }

        # Bağlantı geçmişi
        if ip not in _connections:
            _connections[ip] = []

        # Eski kayıtları temizle
        _connections[ip] = [t for t in _connections[ip] if now - t < TIME_WINDOW]

        # Yeni bağlantı kaydet
        _connections[ip].append(now)
        count = len(_connections[ip])

        # Ban eşiği
        if count >= BAN_THRESHOLD:
            _banned_ips[ip] = now + BAN_DURATION
            return {
                "allowed": False,
                "reason": f"Banned: {count} connections in {TIME_WINDOW}s",
                "ban_remaining": BAN_DURATION,
            }

        # Eşzamanlı bağlantı limiti
        if count > MAX_CONNECTIONS_PER_IP:
            return {
                "allowed": True,
                "reason": "rate_limited",
                "delay": min(count * 2, 30),  # Artan gecikme
            }

        return {"allowed": True, "reason": "ok", "delay": 0}


def ban_ip(ip: str, duration: int = 3600):
    """Manuel IP banlama"""
    with _lock:
        _banned_ips[ip] = time.time() + duration


def unban_ip(ip: str):
    with _lock:
        _banned_ips.pop(ip, None)


def get_banned_ips() -> dict:
    now = time.time()
    with _lock:
        return {ip: round(until - now) for ip, until in _banned_ips.items() if until > now}