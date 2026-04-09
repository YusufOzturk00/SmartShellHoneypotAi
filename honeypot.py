import socket
import threading
import paramiko
import time
import os
import signal
import sys
from core.container_manager import (
    create_session_container,
    get_container_exec,
    destroy_session_container,
    generate_session_id,
    get_active_sessions,
)
from core.pty_bridge import bridge, get_session_commands, get_session_recording
from core.command_logger import classify_command
from core.adaptive_decoy import AdaptiveDecoyEngine

# Global adaptive decoy engine
decoy_engine = AdaptiveDecoyEngine()
from core.llm_analyst import analyze_session, generate_adaptive_decoy, generate_attacker_profile
from core.threat_intel import get_ip_intel
from core.alert_manager import send_alert
from core.rate_limiter import check_rate_limit
from core.event_bus import emit_event, on_event
from core.database import insert_log

# --- SSH HOST KEY ---
KEY_FILE = "data/host_key.pem"

def load_or_generate_host_key():
    if os.path.exists(KEY_FILE):
        return paramiko.RSAKey.from_private_key_file(KEY_FILE)
    key = paramiko.RSAKey.generate(2048)
    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    key.write_private_key_file(KEY_FILE)
    return key

HOST_KEY = load_or_generate_host_key()

# --- VALID CREDENTIALS (Tuzak) ---
VALID_CREDS = {
    ("root", "toor"),
    ("root", "123456"),
    ("root", "password"),
    ("root", "root"),
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "password123"),
    ("postgres", "P@ssw0rd2024!"),
    ("postgres", "postgres"),
    ("dba_user", "dba2024"),
    ("ahmet", "Ahmet2024!"),
}

# --- AUTH TRACKER ---
ATTEMPT_TRACKER = {}
SESSION_CREDS = {}


def save_log(log_type, message, details=None):
    if details is None:
        details = {}

    # Threat intel ekle
    ip = details.get("ip")
    if ip:
        intel = get_ip_intel(ip)
        details["geo"] = {
            "country": intel.get("country"),
            "city": intel.get("city"),
            "isp": intel.get("isp"),
        }

    insert_log(log_type, message, details)

    colors = {
        "INFO": "\033[92m",
        "WARNING": "\033[93m",
        "ALERT": "\033[91m",
        "CRITICAL": "\033[95m",
    }
    color = colors.get(log_type, "\033[0m")
    ts = time.strftime("%H:%M:%S")
    print(f"{color}[{ts}] [{log_type}] {message}\033[0m")


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.username = ""
        self.password = ""

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        self.password = password

        ip = self.client_ip
        attempts = ATTEMPT_TRACKER.get(ip, 0) + 1
        ATTEMPT_TRACKER[ip] = attempts

        # Gerçekçi gecikme (artan)
        delay = 0.5 + (0.3 * min(attempts, 8))
        time.sleep(delay)

        save_log("WARNING", f"Login #{attempts}: {username}:{'*' * len(password)}", {
            "ip": ip,
            "username": username,
            "password": password,
            "attempt": attempts,
        })

        # İlk deneme her zaman başarısız
        if attempts < 1:
            return paramiko.AUTH_FAILED

        # Bilinen credential kontrolü
        if (username, password) in VALID_CREDS:
            save_log("ALERT", f"🚨 LOGIN SUCCESS: {username}", {
                "ip": ip, "username": username, "score": 50,
            })
            send_alert("ALERT", {
                "event": "successful_login",
                "ip": ip,
                "username": username,
                "attempt": attempts,
            })
            return paramiko.AUTH_SUCCESSFUL

        # Brute-force tuzağı: 3+ denemede kabul et
        if attempts >= 3:
            save_log("ALERT", f"🚨 BRUTE-FORCE TRAP: {username} ({attempts} attempts)", {
                "ip": ip, "username": username,
                "password": password, "score": 80,
            })
            send_alert("CRITICAL", {
                "event": "bruteforce_success",
                "ip": ip,
                "username": username,
                "attempts": attempts,
            })
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        return True

    def check_channel_exec_request(self, channel, command):
        """'ssh user@host command' tarzı tek komut çalıştırma"""
        self.event.set()
        return True


def handle_client(client_socket, addr):
    client_ip = addr[0]
    session_id = generate_session_id()

    # Rate limit kontrolü
    limit = check_rate_limit(client_ip)
    if not limit["allowed"]:
        save_log("WARNING", f"Rate limited: {client_ip} ({limit['reason']})", {
            "ip": client_ip, "reason": limit["reason"],
        })
        client_socket.close()
        return

    if limit.get("delay", 0) > 0:
        time.sleep(limit["delay"])

    # Threat intel
    intel = get_ip_intel(client_ip)

    save_log("INFO", f"Yeni bağlantı: {client_ip} [{intel.get('country', '?')}]", {
        "ip": client_ip,
        "session_id": session_id,
        "intel": intel,
    })

    emit_event("new_connection", {
        "session_id": session_id,
        "ip": client_ip,
        "intel": intel,
    })

    # SSH Transport kurulumu
    transport = paramiko.Transport(client_socket)
    transport.local_version = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4"
    transport.add_server_key(HOST_KEY)

    server = HoneypotServer(client_ip)
    try:
        transport.start_server(server=server)
    except Exception as e:
        save_log("WARNING", f"SSH handshake failed: {e}", {"ip": client_ip})
        return

    chan = transport.accept(30)
    if chan is None:
        save_log("INFO", "Channel timeout - scanner probe", {"ip": client_ip})
        return

    server.event.wait(15)
    if not server.event.is_set():
        chan.close()
        return

    # Credential'ları kaydet
    SESSION_CREDS[session_id] = {
        "username": server.username,
        "password": server.password,
    }

    # --- CONTAINER BAŞLAT ---
    try:
        container_id = create_session_container(session_id, client_ip)
        save_log("INFO", f"Container started: {container_id[:12]}", {
            "session_id": session_id, "ip": client_ip,
        })
    except Exception as e:
        save_log("ALERT", f"Container error: {e}", {"ip": client_ip})
        chan.send("System maintenance in progress. Please try again later.\r\n")
        chan.close()
        return

    # --- PTY BAĞLANTISI ---
    adaptive_commands = []

    try:
        container_sock = get_container_exec(session_id)
        if not container_sock:
            chan.close()
            destroy_session_container(session_id)
            return

        def on_command(sid, cmd):
            classify_command(sid, cmd, client_ip)
            adaptive_commands.append(cmd)

            # Her 5 komutta bir adaptif decoy olustur
            if len(adaptive_commands) % 5 == 0 and len(adaptive_commands) >= 5:
                print(f"\033[36m[DECOY TRIGGER] {len(adaptive_commands)} komut, decoy uretiliyor...\033[0m")
                try:
                    decoy = generate_adaptive_decoy(sid, adaptive_commands[-5:])
                    print(f"\033[36m[DECOY RESULT] action={decoy.get('action')}, interest={decoy.get('interest')}, files={len(decoy.get('files',[]))} error={decoy.get('error','none')}\033[0m")
                    if decoy.get("action") != "none" and decoy.get("files"):
                        import base64
                        created_files = []
                        for f_info in decoy.get("files", [])[:3]:
                            fpath = f_info.get("path", "")
                            fcontent = f_info.get("content", "")
                            if not fpath or not fcontent or ".." in fpath:
                                continue
                            try:
                                # Konteyner icinde dizin olustur
                                dir_path = "/".join(fpath.split("/")[:-1])
                                from core.container_manager import exec_in_container
                                if dir_path:
                                    exec_in_container(session_id, f"mkdir -p {dir_path}")
                                # Dosya yaz (base64 ile guvenli)
                                b64 = base64.b64encode(fcontent.encode()).decode()
                                exec_in_container(session_id, f"/bin/bash -c 'echo {b64} | base64 -d > {fpath}'")
                                # Tarihi eskiye ayarla
                                exec_in_container(session_id, f"touch -t 202401120830 {fpath}")
                                created_files.append(fpath)
                            except Exception as fe:
                                pass
                        if created_files:
                            from core.database import insert_log
                            insert_log("INFO", f"Adaptive decoys planted: {len(created_files)}", {
                                "session_id": sid,
                                "interest": decoy.get("interest", "unknown"),
                                "files": created_files,
                                "reasoning": decoy.get("reasoning", ""),
                            })
                            print(f"\033[35m[DECOY] \U0001f3ad {len(created_files)} tuzak olusturuldu "
                                  f"[{decoy.get('interest', '?')}]: {created_files}\033[0m")
                        emit_event("adaptive_decoy", {
                            "session_id": sid,
                            "decoy": decoy,
                            "planted_files": created_files,
                        })
                except Exception as decoy_err:
                    import traceback
                    print(f"[DECOY ERROR] {decoy_err}")
                    traceback.print_exc()

        # Köprüyü başlat
        bridge(chan, container_sock, session_id, client_ip, on_input_line=on_command)

    except Exception as e:
        save_log("WARNING", f"Bridge error: {e}", {"session_id": session_id})
    finally:
        # --- OTURUM BİTTİ ---
        commands = get_session_commands(session_id)
        recording = get_session_recording(session_id)

        # Forensic data topla
        forensic = destroy_session_container(session_id)

        save_log("INFO", f"Session ended. {len(commands)} commands.", {
            "session_id": session_id,
            "ip": client_ip,
            "total_commands": len(commands),
            "duration": forensic.get("session_duration_seconds", 0),
            "fs_changes": len(forensic.get("filesystem_changes", [])),
        })

        # Session recording kaydet
        if recording:
            rec_dir = "data/recordings"
            os.makedirs(rec_dir, exist_ok=True)
            rec_file = os.path.join(rec_dir, f"{session_id}.cast")
            with open(rec_file, "w") as f:
                f.write(recording)

        # LLM ile oturum analizi
        if commands:
            try:
                analysis = analyze_session(session_id, commands, client_ip, intel)
                threat = analysis.get("threat_level", "UNKNOWN")

                # Saldırgan profili analizi
                profile = generate_attacker_profile(session_id, commands, analysis, client_ip)
                
                save_log("ALERT", f"📊 SESSION REPORT [{threat}]", {
                    "session_id": session_id,
                    "ip": client_ip,
                    "analysis": analysis,
                    "attacker_profile": profile,
                    "forensic_summary": {
                        "fs_changes": len(forensic.get("filesystem_changes", [])),
                        "duration": forensic.get("session_duration_seconds"),
                    },
                })
                
                # Saldırgan profilini detaylı yazdır
                if profile.get("profile") != "analysis_failed":
                    print(f"\033[94m\n{'='*60}\033[0m")
                    print(f"\033[94m🔍 ATTACKER PROFILE ANALYSIS\033[0m")
                    print(f"\033[94m{'='*60}\033[0m")
                    print(f"\033[94mType: {profile.get('psychology', {}).get('profile_type', '?')}\033[0m")
                    print(f"\033[94mPrimary Goal: {profile.get('primary_objective', {}).get('goal', '?')}\033[0m")
                    print(f"\033[94mNext Action: {profile.get('next_steps', {}).get('immediate_next_action', '?')}\033[0m")
                    print(f"\033[94m24h Plan: {profile.get('next_steps', {}).get('24_hour_plan', '?')}\033[0m")
                    print(f"\033[94mPsych Summary: {profile.get('psychological_assessment', {}).get('summary', '?')}\033[0m")
                    print(f"\033[94m{'='*60}\033[0m\n")

                # Yüksek tehdit → anında alert
                if threat in ("HIGH", "CRITICAL"):
                    send_alert("CRITICAL", {
                        "event": "high_threat_session",
                        "session_id": session_id,
                        "ip": client_ip,
                        "threat_level": threat,
                        "summary": analysis.get("summary", ""),
                        "commands_count": len(commands),
                    })

            except Exception as e:
                save_log("WARNING", f"Analysis error: {e}", {"session_id": session_id})

        # Temizlik
        SESSION_CREDS.pop(session_id, None)

        try:
            chan.close()
        except:
            pass
        try:
            transport.close()
        except:
            pass


def start_honeypot(port=2225):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(100)

    # Graceful shutdown
    def shutdown(sig, frame):
        print("\n\033[93m[!] Shutting down honeypot...\033[0m")
        sessions = get_active_sessions()
        for s in sessions:
            destroy_session_container(s["session_id"])
        sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print("\033[93m")
    print("╔═══════════════════════════════════════════════════════╗")
    print("║          🍯 AI HONEYPOT v3.0 - PRODUCTION            ║")
    print(f"║  Port: {port}                                          ║")
    print("║  Engine: Docker Container + PTY Bridge                ║")
    print("║  Detection: MITRE ATT&CK + LLM Analyst               ║")
    print("║  Features: Adaptive Decoy | Session Replay | Alerting ║")
    print("╚═══════════════════════════════════════════════════════╝")
    print("\033[0m")

    while True:
        try:
            client, addr = sock.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client, addr),
                daemon=True,
                name=f"client-{addr[0]}",
            )
            t.start()
        except OSError:
            break


if __name__ == "__main__":
    port = int(os.environ.get("HONEYPOT_PORT", 2225))
    start_honeypot(port)