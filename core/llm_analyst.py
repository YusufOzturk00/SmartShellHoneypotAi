import json
import time
from core.llm_engine import get_ai_response
from core.event_bus import emit_event


def analyze_session(session_id: str, commands: list, client_ip: str, intel: dict = None) -> dict:
    """Oturum bittiğinde tüm komutları derinlemesine analiz et"""

    if not commands:
        return {"threat_level": "LOW", "summary": "Empty session - likely automated scanner"}

    cmd_timeline = "\n".join([f"  [{i+1}] {c}" for i, c in enumerate(commands)])

    intel_section = ""
    if intel:
        intel_section = f"""
    Attacker Intelligence:
    - Country: {intel.get('country', 'Unknown')} ({intel.get('country_code', 'XX')})
    - ISP: {intel.get('isp', 'Unknown')}
    - Organization: {intel.get('org', '-')}
    - Abuse Score: {intel.get('abuse_score', 0)}/100
    - Tor Exit Node: {intel.get('is_tor', False)}
    - Threat Tags: {', '.join(intel.get('threat_tags', []))}
    """

    prompt = f"""
    You are an elite SOC Analyst and Threat Hunter.
    Analyze this SSH honeypot session with precision.

    Session ID: {session_id}
    Attacker IP: {client_ip}
    Total Commands: {len(commands)}
    Session Duration: ~{len(commands) * 3} seconds (estimated)
    {intel_section}

    Commands (chronological order):
    {cmd_timeline}

    Provide analysis as VALID JSON only:
    {{
        "threat_level": "LOW|MEDIUM|HIGH|CRITICAL",
        "confidence": 0.0-1.0,
        "attacker_profile": {{
            "type": "script_kiddie|opportunistic|advanced|apt|insider",
            "skill_level": 1-10,
            "likely_motivation": "financial|espionage|destruction|curiosity|research",
            "estimated_experience": "novice|intermediate|expert"
        }},
        "kill_chain": {{
            "current_stage": "reconnaissance|initial_access|execution|persistence|privilege_escalation|credential_access|lateral_movement|exfiltration|impact",
            "completed_stages": ["list of stages observed"],
            "next_likely_action": "what they would do next"
        }},
        "mitre_summary": [
            {{"technique_id": "Txxxx", "name": "...", "evidence": "command that triggered"}}
        ],
        "iocs": {{
            "suspicious_ips": ["any IPs found in commands"],
            "suspicious_domains": ["any domains found"],
            "suspicious_files": ["files created or accessed"],
            "suspicious_commands": ["most dangerous commands"]
        }},
        "summary": "3-4 sentence executive summary for SOC team",
        "recommended_actions": [
            "actionable recommendation 1",
            "actionable recommendation 2"
        ]
    }}

    Return ONLY valid JSON.
    """

    try:
        raw = get_ai_response(prompt).strip()

        # JSON bloğunu çıkar (bazen LLM ```json ... ``` ile sarar)
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0]
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0]

        result = json.loads(raw.strip())

        emit_event("session_analyzed", {
            "session_id": session_id,
            "threat_level": result.get("threat_level"),
            "attacker_type": result.get("attacker_profile", {}).get("type"),
        })

        return result

    except json.JSONDecodeError:
        return {
            "threat_level": "MEDIUM",
            "summary": f"Analysis parsing failed. Session had {len(commands)} commands.",
            "commands": commands[:20],
            "raw_analysis": raw[:1000] if 'raw' in dir() else "No response",
        }
    except Exception as e:
        return {
            "threat_level": "UNKNOWN",
            "summary": f"Analysis error: {str(e)}",
            "total_commands": len(commands),
        }


def generate_adaptive_decoy(session_id: str, recent_commands: list) -> dict:
    """Saldirganin davranisina gore dinamik tuzak oner - Gelistirilmis versiyon"""

    if len(recent_commands) < 3:
        return {"action": "none"}

    cmd_list = ", ".join(recent_commands[-10:])

    # Saldirganin ilgi alanini tespit et
    interest_keywords = {
        "database": ["sql", "dump", "backup", "mysql", "postgres", "psql", "db", "mongo"],
        "credentials": ["passwd", "shadow", "password", "secret", "token", "auth", "hash", "cred"],
        "crypto_keys": ["pem", "key", "rsa", "ssh", "ssl", "cert", "id_rsa", "private"],
        "cloud": ["aws", "azure", "gcp", "terraform", "docker", "kube", "s3", "ec2", "iam"],
        "network": ["ifconfig", "ip a", "netstat", "ss ", "arp", "route", "nmap", "hosts"],
        "web": ["nginx", "apache", "http", "www", "html", "php", "config.php", "wp-config"],
        "source_code": [".py", ".js", ".go", ".java", ".sh", "git", "repo", "src"],
        "logs": ["log", "syslog", "auth.log", "access.log", "journal", "audit"]
    }

    detected_interests = []
    for cmd in recent_commands[-10:]:
        cmd_lower = cmd.lower()
        for category, patterns in interest_keywords.items():
            for p in patterns:
                if p in cmd_lower:
                    detected_interests.append(category)
                    break

    # En cok tespit edilen ilgi alani
    if detected_interests:
        from collections import Counter
        top_interest = Counter(detected_interests).most_common(1)[0][0]
    else:
        top_interest = "general"

    # general bile olsa LLM'e gonder, komutlardan anlam cikarsin
    prompt = f"""
    You are an elite deception technology AI on a Turkish bank server (prod-db-01, FinansBank).
    
    The attacker is interested in: {top_interest}
    Recent commands: {cmd_list}
    
    Generate exactly 3 realistic decoy files to plant in the container.
    These files should look real and attract the attacker further.
    Use realistic Turkish names, IPs (192.168.x.x), and bank-related data.
    File timestamps should look like January 2024.
    
    RULES:
    - Paths must be absolute (start with /)
    - Content must be realistic and multi-line
    - No ".." in paths
    - Files should look like they were forgotten by a careless admin
    
    Return ONLY a valid JSON object:
    {{
        "action": "create_files",
        "interest": "{top_interest}",
        "files": [
            {{
                "path": "/full/path/filename.ext",
                "content": "realistic multi-line content here"
            }},
            {{
                "path": "/full/path/filename2.ext",
                "content": "realistic multi-line content here"
            }},
            {{
                "path": "/full/path/filename3.ext",
                "content": "realistic multi-line content here"
            }}
        ],
        "reasoning": "why these files will attract this attacker"
    }}

    Return ONLY valid JSON. No markdown, no explanation.
    """

    for attempt in range(2):
      try:
        raw = get_ai_response(prompt).strip()
        
        # JSON blogu cikar (cesitli formatlar)
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0]
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0]
        
        raw = raw.strip()
        
        # Bazen LLM json'dan once/sonra text ekliyor, { } arasini bul
        if not raw.startswith("{"):
            start = raw.find("{")
            if start != -1:
                raw = raw[start:]
        if not raw.endswith("}"):
            end = raw.rfind("}")
            if end != -1:
                raw = raw[:end+1]
        
        # Bozuk escape karakterlerini duzelt
        import re as _re
        raw = _re.sub(r'[-]', lambda m: '\\n' if m.group() == '\n' else '', raw)
        
        result = json.loads(raw.strip())
        
        # Validate
        if "files" not in result:
            result["files"] = []
        if "action" not in result:
            result["action"] = "create_files" if result["files"] else "none"
        if "interest" not in result:
            result["interest"] = top_interest
        
        return result

      except json.JSONDecodeError:
            if attempt == 0:
                continue  # Tekrar dene
            return {"action": "none", "error": "JSON parse failed"}
      except Exception as e:
            if attempt == 0:
                continue
            return {"action": "none", "error": str(e)}
    return {"action": "none", "error": "all retries failed"}
