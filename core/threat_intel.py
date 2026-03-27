import requests
import time
import random
import os
from functools import lru_cache

IP_CACHE = {}
CACHE_TTL = 3600  # 1 saat


def get_ip_intel(ip: str) -> dict:
    """IP hakkında coğrafi ve tehdit bilgisi topla"""

    # Cache kontrol
    cached = IP_CACHE.get(ip)
    if cached and (time.time() - cached["_cached_at"]) < CACHE_TTL:
        return cached

    result = {
        "ip": ip,
        "country": "Unknown",
        "country_code": "XX",
        "city": "-",
        "isp": "Unknown",
        "org": "-",
        "is_proxy": False,
        "is_tor": False,
        "abuse_score": 0,
        "threat_tags": [],
    }

    # Yerel IP'ler için sahte ama gerçekçi intel
    if _is_private_ip(ip):
        fake_profiles = [
            {
                "country": "China", "country_code": "CN", "city": "Beijing",
                "isp": "Chinanet", "org": "China Telecom",
                "abuse_score": 85, "threat_tags": ["scanner", "brute_force"],
            },
            {
                "country": "Russia", "country_code": "RU", "city": "Moscow",
                "isp": "Rostelecom", "org": "Gov Network",
                "abuse_score": 90, "threat_tags": ["apt", "credential_stuffing"],
            },
            {
                "country": "North Korea", "country_code": "KP", "city": "Pyongyang",
                "isp": "Star JV", "org": "Lazarus Group",
                "abuse_score": 100, "threat_tags": ["apt", "ransomware", "crypto_theft"],
            },
            {
                "country": "Iran", "country_code": "IR", "city": "Tehran",
                "isp": "TIC", "org": "APT33",
                "abuse_score": 88, "threat_tags": ["apt", "destructive"],
            },
            {
                "country": "USA", "country_code": "US", "city": "Langley",
                "isp": "DoD Network", "org": "Unknown Gov Entity",
                "abuse_score": 40, "threat_tags": ["recon"],
            },
        ]
        fake = random.choice(fake_profiles)
        result.update(fake)
        result["_cached_at"] = time.time()
        IP_CACHE[ip] = result
        return result

    # Gerçek IP → GeoIP
    result = _query_geoip(ip, result)

    # AbuseIPDB sorgusu
    result = _query_abuseipdb(ip, result)

    result["_cached_at"] = time.time()
    IP_CACHE[ip] = result
    return result


def _is_private_ip(ip: str) -> bool:
    return (
        ip.startswith("127.") or
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        ip.startswith("172.16.") or
        ip.startswith("172.17.") or
        ip == "localhost"
    )


def _query_geoip(ip: str, result: dict) -> dict:
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,org,proxy",
            timeout=3,
        )
        if resp.status_code == 200:
            data = resp.json()
            result["country"] = data.get("country", "Unknown")
            result["country_code"] = data.get("countryCode", "XX")
            result["city"] = data.get("city", "-")
            result["isp"] = data.get("isp", "Unknown")
            result["org"] = data.get("org", "-")
            result["is_proxy"] = data.get("proxy", False)
    except:
        pass
    return result


def _query_abuseipdb(ip: str, result: dict) -> dict:
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        return result
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=3,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {})
            result["abuse_score"] = data.get("abuseConfidenceScore", 0)
            result["is_tor"] = data.get("isTor", False)
            if data.get("totalReports", 0) > 10:
                result["threat_tags"].append("known_attacker")
            if data.get("isTor"):
                result["threat_tags"].append("tor_exit_node")
    except:
        pass
    return result