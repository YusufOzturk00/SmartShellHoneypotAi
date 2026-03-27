import threading
import select
import time
import json
from core.event_bus import emit_event

COMMAND_BUFFER = {}
SESSION_RECORDINGS = {}


class SessionRecorder:
    """Asciinema v2 formatında terminal kaydı"""

    def __init__(self, session_id: str):
        self.session_id = session_id
        self.start_time = time.time()
        self.events = []
        self.header = {
            "version": 2,
            "width": 120,
            "height": 40,
            "timestamp": int(self.start_time),
            "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
        }

    def record_output(self, data: bytes):
        elapsed = time.time() - self.start_time
        text = data.decode("utf-8", errors="replace")
        self.events.append([round(elapsed, 6), "o", text])

    def record_input(self, data: bytes):
        elapsed = time.time() - self.start_time
        text = data.decode("utf-8", errors="replace")
        self.events.append([round(elapsed, 6), "i", text])

    def to_asciicast(self) -> str:
        lines = [json.dumps(self.header)]
        for event in self.events:
            lines.append(json.dumps(event))
        return "\n".join(lines)


def bridge(chan, container_sock, session_id: str, client_ip: str, on_input_line=None):
    """
    Paramiko kanalı ↔ Docker exec soketi arasında
    byte-level köprü. Session recording dahil.
    """
    sock = container_sock._sock

    input_buf = b""
    COMMAND_BUFFER[session_id] = []
    recorder = SessionRecorder(session_id)
    SESSION_RECORDINGS[session_id] = recorder

    alive = threading.Event()
    alive.set()

    def forward_to_container():
        """Kullanıcı → Container (input yakalama dahil)"""
        nonlocal input_buf
        try:
            while alive.is_set():
                data = chan.recv(4096)
                if not data:
                    break

                recorder.record_input(data)

                # Satır bazlı komut yakalama
                input_buf += data
                while b"\r" in input_buf or b"\n" in input_buf:
                    for sep in [b"\r\n", b"\r", b"\n"]:
                        if sep in input_buf:
                            line_bytes, input_buf = input_buf.split(sep, 1)
                            line = line_bytes.decode("utf-8", errors="ignore").strip()
                            # ANSI escape kodlarını temizle
                            import re
                            line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line)
                            line = line.strip()
                            if line:
                                COMMAND_BUFFER[session_id].append(line)
                                print(f"\033[33m[BRIDGE] Komut yakalandi: '{line}' (toplam: {len(COMMAND_BUFFER[session_id])})\033[0m")
                                if on_input_line:
                                    on_input_line(session_id, line)
                                emit_event("command_entered", {
                                    "session_id": session_id,
                                    "command": line,
                                    "ip": client_ip,
                                })
                            break

                sock.sendall(data)
        except (OSError, EOFError):
            pass
        finally:
            alive.clear()

    def forward_to_user():
        """Container → Kullanıcı (output yakalama dahil)"""
        try:
            while alive.is_set():
                ready, _, _ = select.select([sock], [], [], 0.5)
                if ready:
                    data = sock.recv(16384)
                    if not data:
                        break
                    recorder.record_output(data)
                    chan.sendall(data)
        except (OSError, EOFError):
            pass
        finally:
            alive.clear()

    t1 = threading.Thread(target=forward_to_container, daemon=True, name=f"in-{session_id[:8]}")
    t2 = threading.Thread(target=forward_to_user, daemon=True, name=f"out-{session_id[:8]}")
    t1.start()
    t2.start()

    # Biri bitene kadar bekle
    t1.join()
    alive.clear()
    t2.join(timeout=2)


def get_session_commands(session_id: str) -> list:
    return COMMAND_BUFFER.pop(session_id, [])


def get_session_recording(session_id: str) -> str:
    recorder = SESSION_RECORDINGS.pop(session_id, None)
    if recorder:
        return recorder.to_asciicast()
    return ""