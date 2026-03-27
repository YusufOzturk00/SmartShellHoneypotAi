import docker
import uuid
import time
import threading
from core.event_bus import emit_event

client = docker.from_env()

IMAGE_NAME = "honeypot-jail:latest"
ACTIVE_CONTAINERS = {}
CONTAINER_METADATA = {}

# Container başına kaynak limitleri
CONTAINER_LIMITS = {
    "mem_limit": "64m",
    "memswap_limit": "64m",        # Swap yok
    "cpu_period": 100000,
    "cpu_quota": 10000,             # %10 CPU
    "pids_limit": 50,               # Fork bomb koruması
    "storage_opt": {"size": "100m"} # Disk limiti (overlay2 gerekli)
}

# Güvenlik ayarları
SECURITY_OPTS = {
    "network_mode": "none",
    "security_opt": ["no-new-privileges:true"],
    "cap_drop": ["ALL"],
    "cap_add": ["CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE"],
    "read_only": False,
    "tmpfs": {"/tmp": "size=10m,noexec"},
}


def create_session_container(session_id: str, client_ip: str) -> str:
    """Her SSH oturumu için izole container başlat"""
    container_name = f"hp-{session_id[:8]}"

    try:
        # Storage opt sadece overlay2 ile çalışır, yoksa kaldır
        limits = CONTAINER_LIMITS.copy()
        try:
            info = client.info()
            if info.get("Driver") != "overlay2":
                limits.pop("storage_opt", None)
        except:
            limits.pop("storage_opt", None)

        container = client.containers.run(
            IMAGE_NAME,
            name=container_name,
            hostname="prod-db-01",
            domainname="finansbank.local",
            detach=True,
            stdin_open=True,
            tty=True,
            environment={
                "TERM": "xterm-256color",
                "HOME": "/root",
                "USER": "root",
                "SHELL": "/bin/bash",
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "PS1": "\\[\\033[01;31m\\]root\\[\\033[00m\\]@\\[\\033[01;32m\\]prod-server\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]# ",
                "LANG": "en_US.UTF-8",
                # Canary: bu değişken okunursa loglanır
                "DB_PASSWORD": "Finans_2024_XKD!",
                "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
                "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            },
            labels={
                "honeypot": "true",
                "session_id": session_id,
                "client_ip": client_ip,
            },
            **SECURITY_OPTS,
            **limits,
        )

        ACTIVE_CONTAINERS[session_id] = container
        CONTAINER_METADATA[session_id] = {
            "container_id": container.id,
            "client_ip": client_ip,
            "start_time": time.time(),
            "name": container_name,
        }

        # Escape detection başlat
        _start_escape_monitor(session_id, container)

        # Max session süresi (30 dk)
        _start_session_timer(session_id, timeout=1800)

        emit_event("container_created", {
            "session_id": session_id,
            "container_id": container.id[:12],
            "client_ip": client_ip,
        })

        return container.id

    except docker.errors.ImageNotFound:
        raise RuntimeError(f"Honeypot image '{IMAGE_NAME}' not found. Run: docker build -t {IMAGE_NAME} -f Dockerfile.honeypot .")
    except Exception as e:
        raise RuntimeError(f"Container creation failed: {e}")


def get_container_exec(session_id: str):
    """Container'da interaktif bash başlat, soket döndür"""
    container = ACTIVE_CONTAINERS.get(session_id)
    if not container:
        return None

    exec_id = client.api.exec_create(
        container.id,
        "/bin/bash --login -i",
        stdin=True,
        tty=True,
        stdout=True,
        stderr=True,
    )

    sock = client.api.exec_start(exec_id["Id"], socket=True, tty=True)
    return sock


def exec_in_container(session_id: str, command: str) -> str:
    """Container icinde komut calistir ve ciktiyi don"""
    container = ACTIVE_CONTAINERS.get(session_id)
    if not container:
        return ""
    
    try:
        exec_result = client.api.exec_create(
            container.id,
            ["/bin/bash", "-c", command],
            stdout=True,
            stderr=True,
        )
        output = client.api.exec_start(exec_result["Id"])
        return output.decode("utf-8", errors="ignore")
    except Exception as e:
        print(f"[CONTAINER] exec_in_container error: {e}")
        return ""


def destroy_session_container(session_id: str) -> dict:
    """Oturum bitince container'ı temizle, forensic data topla"""
    container = ACTIVE_CONTAINERS.pop(session_id, None)
    metadata = CONTAINER_METADATA.pop(session_id, {})

    forensic_data = {}

    if container:
        try:
            # Container içindeki değişiklikleri yakala (forensic)
            diff = client.api.diff(container.id)
            forensic_data["filesystem_changes"] = diff or []
        except:
            forensic_data["filesystem_changes"] = []

        try:
            # Container loglarını al
            logs = container.logs(stdout=True, stderr=True, tail=500)
            forensic_data["container_logs"] = logs.decode("utf-8", errors="ignore")[-5000:]
        except:
            forensic_data["container_logs"] = ""

        try:
            duration = time.time() - metadata.get("start_time", time.time())
            forensic_data["session_duration_seconds"] = round(duration, 1)
        except:
            pass

        try:
            container.stop(timeout=3)
            container.remove(force=True)
        except:
            try:
                container.remove(force=True)
            except:
                pass

        emit_event("container_destroyed", {
            "session_id": session_id,
            "forensic": forensic_data,
        })

    return forensic_data


def _start_escape_monitor(session_id: str, container):
    """Container escape denemelerini izle"""
    def monitor():
        dangerous_indicators = [
            "mount", "/proc/self/exe", "nsenter",
            "/var/run/docker.sock", "capsh", "breakout",
        ]
        try:
            while session_id in ACTIVE_CONTAINERS:
                # Container'daki son komutları kontrol et
                try:
                    exec_result = client.api.exec_create(
                        container.id, "cat /proc/1/cmdline",
                        stdout=True, stderr=True,
                    )
                    output = client.api.exec_start(exec_result["Id"])
                    output_str = output.decode("utf-8", errors="ignore")

                    for indicator in dangerous_indicators:
                        if indicator in output_str:
                            emit_event("escape_attempt", {
                                "session_id": session_id,
                                "indicator": indicator,
                                "severity": "CRITICAL",
                            })
                            # Anında container'ı öldür
                            destroy_session_container(session_id)
                            return
                except:
                    pass

                time.sleep(5)
        except:
            pass

    t = threading.Thread(target=monitor, daemon=True)
    t.start()


def _start_session_timer(session_id: str, timeout: int):
    """Max session süresi aşıldığında container'ı kapat"""
    def timer():
        time.sleep(timeout)
        if session_id in ACTIVE_CONTAINERS:
            emit_event("session_timeout", {
                "session_id": session_id,
                "timeout": timeout,
            })
            destroy_session_container(session_id)

    t = threading.Thread(target=timer, daemon=True)
    t.start()


def get_active_sessions() -> list:
    """Aktif oturumları listele (dashboard için)"""
    sessions = []
    for sid, meta in CONTAINER_METADATA.items():
        duration = time.time() - meta.get("start_time", time.time())
        sessions.append({
            "session_id": sid,
            "client_ip": meta.get("client_ip"),
            "container": meta.get("name"),
            "duration_seconds": round(duration, 1),
        })
    return sessions


def generate_session_id() -> str:
    return str(uuid.uuid4())