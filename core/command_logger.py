import re
import time
from core.database import insert_log
from core.event_bus import emit_event

# Kapsamlı MITRE ATT&CK eşlemeleri
MITRE_RULES = [
    # ===== RECONNAISSANCE =====
    {
        "pattern": r"\b(id|whoami|who\s+am\s+i)\b",
        "tactic": "Discovery", "technique": "T1033",
        "name": "System Owner/User Discovery", "risk": 15,
    },
    {
        "pattern": r"\b(uname|hostname|hostnamectl|cat\s+/etc/(hostname|machine-id|os-release))\b",
        "tactic": "Discovery", "technique": "T1082",
        "name": "System Information Discovery", "risk": 20,
    },
    {
        "pattern": r"\b(ifconfig|ip\s+(a|addr|route|link)|netstat|ss\s+-[tlnpu]|route\s+-n)\b",
        "tactic": "Discovery", "technique": "T1016",
        "name": "System Network Configuration Discovery", "risk": 30,
    },
    {
        "pattern": r"\b(arp\s+-a|ip\s+neigh|nmap|ping\s+-c|traceroute|dig|nslookup)\b",
        "tactic": "Discovery", "technique": "T1018",
        "name": "Remote System Discovery", "risk": 40,
    },
    {
        "pattern": r"\b(ps\s+(aux|ef|-ef)|top|htop|pgrep|pidof)\b",
        "tactic": "Discovery", "technique": "T1057",
        "name": "Process Discovery", "risk": 25,
    },
    {
        "pattern": r"\b(ls\s+/|find\s+/|locate\s+|tree\s+/|du\s+-[sh])\b",
        "tactic": "Discovery", "technique": "T1083",
        "name": "File and Directory Discovery", "risk": 20,
    },
    {
        "pattern": r"\b(cat\s+/etc/passwd|getent\s+passwd|cut.*:/etc/passwd|awk.*/etc/passwd)\b",
        "tactic": "Discovery", "technique": "T1087",
        "name": "Account Discovery", "risk": 35,
    },
    {
        "pattern": r"\b(df\s+-|mount\s*$|lsblk|fdisk\s+-l|cat\s+/etc/fstab)\b",
        "tactic": "Discovery", "technique": "T1082",
        "name": "Disk/Mount Discovery", "risk": 20,
    },
    {
        "pattern": r"\b(env|printenv|set\s*$|echo\s+\$[A-Z_]|cat\s+/proc/.*/environ)\b",
        "tactic": "Discovery", "technique": "T1082",
        "name": "Environment Variable Discovery", "risk": 30,
    },
    {
        "pattern": r"\b(iptables\s+-[LnvS]|ufw\s+status|firewall-cmd|nft\s+list)\b",
        "tactic": "Discovery", "technique": "T1518",
        "name": "Security Software Discovery", "risk": 40,
    },

    # ===== CREDENTIAL ACCESS =====
    {
        "pattern": r"\b(cat|less|head|tail|grep|strings|xxd).*(passw|shadow|credential|secret|\.env|config\.(php|yml|json|ini))\b",
        "tactic": "Credential Access", "technique": "T1552.001",
        "name": "Credentials In Files", "risk": 80,
    },
    {
        "pattern": r"\b(find|locate|grep\s+-r).*(passw|secret|key|token|credential|\.pem|\.key|id_rsa)\b",
        "tactic": "Credential Access", "technique": "T1552",
        "name": "Unsecured Credentials Search", "risk": 75,
    },
    {
        "pattern": r"\bcat\s+/etc/shadow\b",
        "tactic": "Credential Access", "technique": "T1003.008",
        "name": "Shadow File Access", "risk": 90,
    },
    {
        "pattern": r"\b(cat|less).*\.(pem|key|crt|cert|p12|pfx|jks)\b",
        "tactic": "Credential Access", "technique": "T1552.004",
        "name": "Private Keys Access", "risk": 85,
    },
    {
        "pattern": r"\b(cat|less).*(aws|gcloud|azure|\.kube|kubeconfig)\b",
        "tactic": "Credential Access", "technique": "T1552.001",
        "name": "Cloud Credentials Access", "risk": 90,
    },
    {
        "pattern": r"\b(history|\.bash_history|\.zsh_history)\b",
        "tactic": "Credential Access", "technique": "T1552.003",
        "name": "Bash History Mining", "risk": 50,
    },

    # ===== PERSISTENCE =====
    {
        "pattern": r"\b(crontab\s+-[el]|/etc/cron|at\s+|systemctl\s+(enable|daemon-reload))\b",
        "tactic": "Persistence", "technique": "T1053",
        "name": "Scheduled Task/Job", "risk": 80,
    },
    {
        "pattern": r"\b(useradd|adduser|usermod|passwd\s+\w+)\b",
        "tactic": "Persistence", "technique": "T1136.001",
        "name": "Create/Modify Local Account", "risk": 90,
    },
    {
        "pattern": r"\b(echo.*>>?\s*(/root/)?\.bashrc|echo.*>>?\s*(/root/)?\.profile|echo.*>>?\s*/etc/rc\.local)\b",
        "tactic": "Persistence", "technique": "T1546.004",
        "name": "Shell Profile Modification", "risk": 85,
    },
    {
        "pattern": r"\b(ssh-keygen|echo.*authorized_keys|cat.*authorized_keys)\b",
        "tactic": "Persistence", "technique": "T1098.004",
        "name": "SSH Authorized Keys Modification", "risk": 90,
    },

    # ===== LATERAL MOVEMENT =====
    {
        "pattern": r"\b(ssh\s+\w+@|scp\s+|rsync\s+.*@|sftp\s+)\b",
        "tactic": "Lateral Movement", "technique": "T1021.004",
        "name": "SSH Lateral Movement", "risk": 75,
    },

    # ===== EXFILTRATION =====
    {
        "pattern": r"\b(curl\s+(-X\s+POST|.*-d\s|.*--data)|wget\s+--post)\b",
        "tactic": "Exfiltration", "technique": "T1048",
        "name": "Exfiltration Over HTTP", "risk": 80,
    },
    {
        "pattern": r"\b(nc\s+-[lp]|ncat|socat|/dev/tcp/)\b",
        "tactic": "Exfiltration", "technique": "T1041",
        "name": "Netcat/Reverse Shell", "risk": 95,
    },
    {
        "pattern": r"\b(base64|openssl\s+enc|tar\s+.*\|.*curl|gzip\s+.*\|)\b",
        "tactic": "Exfiltration", "technique": "T1560",
        "name": "Archive/Encode for Exfil", "risk": 70,
    },

    # ===== DEFENSE EVASION =====
    {
        "pattern": r"\b(rm\s+-rf|shred|wipe|srm)\s+.*(log|history|tmp|audit)\b",
        "tactic": "Defense Evasion", "technique": "T1070.004",
        "name": "File Deletion (Log Clearing)", "risk": 75,
    },
    {
        "pattern": r"\b(history\s+-c|unset\s+HISTFILE|export\s+HISTFILE=/dev/null|set\s+\+o\s+history)\b",
        "tactic": "Defense Evasion", "technique": "T1070.003",
        "name": "Clear Command History", "risk": 70,
    },
    {
        "pattern": r"\b(chmod\s+[0-7]{3,4}|chown|chattr)\b",
        "tactic": "Defense Evasion", "technique": "T1222",
        "name": "File Permissions Modification", "risk": 40,
    },

    # ===== EXECUTION =====
    {
        "pattern": r"\b(python[23]?\s+-c|perl\s+-e|ruby\s+-e|php\s+-r|bash\s+-c|sh\s+-c)\b",
        "tactic": "Execution", "technique": "T1059",
        "name": "Scripting Interpreter Execution", "risk": 60,
    },
    {
        "pattern": r"\b(wget\s+.*\|\s*(ba)?sh|curl\s+.*\|\s*(ba)?sh)\b",
        "tactic": "Execution", "technique": "T1059.004",
        "name": "Download and Execute", "risk": 95,
    },
    {
        "pattern": r"\b(chmod\s+\+x\s+.*;\s*\./|\.\/[a-zA-Z])\b",
        "tactic": "Execution", "technique": "T1204",
        "name": "User Execution of Payload", "risk": 80,
    },

    # ===== PRIVILEGE ESCALATION =====
    {
        "pattern": r"\b(sudo\s+|su\s+-|pkexec|doas)\b",
        "tactic": "Privilege Escalation", "technique": "T1548",
        "name": "Sudo/Su Abuse", "risk": 50,
    },
    {
        "pattern": r"\b(find\s+.*-perm\s+.*(4000|2000)|find\s+.*-user\s+root.*-perm)\b",
        "tactic": "Privilege Escalation", "technique": "T1548.001",
        "name": "SUID/SGID Binary Search", "risk": 70,
    },
    {
        "pattern": r"\b(cat\s+/etc/sudoers|sudo\s+-l|visudo)\b",
        "tactic": "Privilege Escalation", "technique": "T1548.003",
        "name": "Sudoers Enumeration", "risk": 65,
    },

    # ===== IMPACT =====
    {
        "pattern": r"\b(rm\s+-rf\s+/|mkfs|dd\s+if=/dev/(zero|urandom)\s+of=/|:(){ :\|:& };:)\b",
        "tactic": "Impact", "technique": "T1485",
        "name": "Data Destruction", "risk": 100,
    },
]


def classify_command(session_id: str, command: str, client_ip: str) -> dict:
    """Komutu MITRE ATT&CK'a göre sınıflandır"""

    matched = []
    max_risk = 0

    for rule in MITRE_RULES:
        if re.search(rule["pattern"], command, re.IGNORECASE):
            matched.append({
                "tactic": rule["tactic"],
                "technique": rule["technique"],
                "name": rule["name"],
                "risk": rule["risk"],
            })
            max_risk = max(max_risk, rule["risk"])

    if not matched:
        matched = [{"tactic": "Execution", "technique": "T1059", "name": "Command-Line Interface", "risk": 5}]
        max_risk = 5

    details = {
        "session_id": session_id,
        "command": command,
        "ip": client_ip,
        "risk_score": max_risk,
        "mitre_tactics": matched,
        "timestamp": time.time(),
    }

    log_type = "INFO"
    if max_risk >= 80:
        log_type = "ALERT"
    elif max_risk >= 40:
        log_type = "WARNING"

    insert_log(log_type, f"[{session_id[:8]}] {command}", details)

    emit_event("command_classified", details)

    return details