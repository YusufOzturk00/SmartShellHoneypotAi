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


def analyze_attacker_psychology(session_id: str, commands: list, analysis: dict, intel: dict, client_ip: str) -> dict:
    """Saldırganın psikolojisini, amacını ve sonraki hamlesini analiz et"""

    if not commands:
        return {"error": "no commands"}

    cmd_list = "\n".join([f"  [{i+1}] {c}" for i, c in enumerate(commands[:30])])
    
    threat_level = analysis.get("threat_level", "UNKNOWN")
    attacker_type = analysis.get("attacker_profile", {}).get("type", "unknown")
    
    intel_info = f"""
    Attacker Intelligence:
    - Country: {intel.get('country', '?')}
    - ISP: {intel.get('isp', '?')}
    - Abuse Score: {intel.get('abuse_score', 0)}/100
    - Threat Tags: {', '.join(intel.get('threat_tags', [])[:3])}
    """ if intel else ""

    prompt = f"""
    You are a cyber psychologist and threat analyst. Analyze this attacker's behavior, mindset, and predict their next moves.

    Session ID: {session_id}
    Attacker IP: {client_ip}
    Threat Level: {threat_level}
    Attacker Type: {attacker_type}
    
    {intel_info}

    Commands executed (in order):
    {cmd_list}

    Analyze and return ONLY valid JSON:
    {{
        "type": "script_kiddie|opportunistic|advanced|apt|insider|researcher",
        "primary_goal": "short description of main objective in English",
        "primary_goal_tr": "Türkçe açıklaması",
        
        "psychology": {{
            "mindset": "saldırganın düşünüş tarzı ve karakteri (Türkçe)",
            "intelligence_level": "naif|average|intelligent|expert (1-10 scale)",
            "patience": "low|medium|high (bekleyen mi hızlı mı hareket ediyor)",
            "boldness": "cautious|moderate|reckless (ne kadar cesur)"
        }},
        
        "estimated_experience": "novice|intermediate|advanced|expert",
        "likely_motivation": "financial|espionage|curiosity|research|sabotage|testing|fun",
        
        "next_24h_prediction": {{
            "action_1": "first likely action (English)",
            "action_1_tr": "Türkçe açıklaması",
            "action_2": "second likely action (English)",
            "action_2_tr": "Türkçe açıklaması",
            "probability": "yüksek|orta|düşük"
        }},
        
        "confidence": 0.5,
        "reasoning": "why you think this way"
    }}

    Return ONLY valid JSON. No markdown.
    """

    try:
        raw = get_ai_response(prompt).strip()
        
        # JSON parse
        if "```json" in raw:
            raw = raw.split("```json")[1].split("```")[0]
        elif "```" in raw:
            raw = raw.split("```")[1].split("```")[0]
        
        raw = raw.strip()
        
        # { } arasını bul
        if not raw.startswith("{"):
            start = raw.find("{")
            if start != -1:
                raw = raw[start:]
        if not raw.endswith("}"):
            end = raw.rfind("}")
            if end != -1:
                raw = raw[:end+1]
        
        result = json.loads(raw.strip())
        return result

    except json.JSONDecodeError:
        return {"error": "json_parse_failed", "raw": raw[:500] if 'raw' in dir() else ""}
    except Exception as e:
        return {"error": str(e)}


def analyze_attacker_psychology(session_id: str, commands: list, analysis: dict, intel: dict, client_ip: str) -> dict:
    """Saldırganın psikolojisini ve sonraki hamlesini analiz et"""
    
    if not commands or not analysis:
        return {"type": "unknown", "primary_goal": "?", "primary_goal_tr": "?", "psychology": {}, "confidence": 0}
    
    cmd_list = "\n".join([f"  [{i+1}] {c}" for i, c in enumerate(commands[:15])])
    threat = analysis.get("threat_level", "UNKNOWN")
    attacker_type = analysis.get("attacker_profile", {}).get("type", "unknown")
    
    prompt = f"""You are an elite cybersecurity behavioral analyst and threat psychologist.

ATTACKER BEHAVIOR ANALYSIS
Session Commands (chronological):
{cmd_list}

Context:
- Threat Level: {threat}
- Detected Type: {attacker_type}
- IP: {client_ip}

DEEP ANALYSIS REQUIRED:
1. Attacker Psychology (mindset, patience, methodology)
2. Primary Motivation (financial, espionage, sabotage, curiosity, learning)
3. Skill Assessment (beginner to expert)
4. Attack Sophistication (chaotic vs methodical)
5. Next 24-hour Predictions (specific actions)
6. Long-term Threat Assessment

Return ONLY valid JSON (no markdown, no code blocks):
{{
    "type": "script_kiddie|opportunistic|advanced|apt|insider|researcher",
    "primary_goal": "Main objective in English (20-60 chars)",
    "primary_goal_tr": "Ana hedef Türkçe (20-60 karakter)",
    
    "psychology": {{
        "mindset": "Saldırganın zihinsel durumu ve yaklaşımı Türkçe (50-80 karakter)",
        "methodology": "Çalışma stili: sabırlı/acele/kaotik/sistematik",
        "intelligence": "novice|intermediate|advanced|expert",
        "patience_level": "low|medium|high",
        "boldness": "cautious|moderate|reckless"
    }},
    
    "motivation": {{
        "primary": "financial|espionage|sabotage|curiosity|learning|testing|revenge",
        "secondary": ["possible secondary motivations"],
        "reasoning": "Why they have this motivation (Türkçe, 50 karakter)"
    }},
    
    "skill_assessment": {{
        "technical_skill": 1-10,
        "operational_security": 1-10,
        "patience": 1-10,
        "knowledge_depth": "surface|moderate|deep",
        "estimated_experience": "fresh|months|years"
    }},
    
    "attack_characteristics": {{
        "sophistication": "basic|intermediate|advanced|expert",
        "planning": "random|planned|very_planned",
        "speed": "slow|moderate|fast|frantic",
        "focus": "scattered|targeted|systematic"
    }},
    
    "next_24h_prediction": {{
        "action_1": "First likely action (English)",
        "action_1_tr": "İlk muhtemel aksiyon (Türkçe)",
        "action_1_timeframe": "minutes|hours|immediately",
        
        "action_2": "Second likely action (English)",
        "action_2_tr": "İkinci muhtemel aksiyon (Türkçe)",
        
        "action_3": "Third likely action (English)",
        "action_3_tr": "Üçüncü muhtemel aksiyon (Türkçe)",
        
        "probability": "low|medium|high"
    }},
    
    "threat_assessment": {{
        "immediate_danger": 1-10,
        "data_breach_risk": 1-10,
        "system_compromise_risk": 1-10,
        "estimated_time_to_critical_breach": "minutes|hours|days|weeks"
    }},
    
    "psychological_profile": "2-3 sentence psychological summary in Turkish",
    "confidence": 0.0-1.0,
    "reasoning": "Brief explanation of analysis (max 100 chars)"
}}

CRITICAL REQUIREMENTS:
- EVERY field MUST have a meaningful value
- No null, no empty strings, no question marks
- If uncertain, use reasonable inferences from command patterns
- Provide Turkish and English versions
- Be specific, not generic"""
    
    for attempt in range(2):
        try:
            raw = get_ai_response(prompt).strip()
            
            # JSON çıkart
            if "```json" in raw:
                raw = raw.split("```json")[1].split("```")[0]
            elif "```" in raw:
                raw = raw.split("```")[1].split("```")[0]
            
            raw = raw.strip()
            
            # { } arasını bul
            if "{" in raw and "}" in raw:
                start = raw.find("{")
                end = raw.rfind("}") + 1
                raw = raw[start:end]
            
            result = json.loads(raw)
            
            # Validate - tüm alanları doldur
            if not result.get("type"):
                result["type"] = attacker_type if attacker_type != "unknown" else "opportunistic"
            if not result.get("primary_goal"):
                result["primary_goal"] = "Reconnaissance and system access"
            if not result.get("primary_goal_tr"):
                result["primary_goal_tr"] = "Sistem keşfi ve erişim sağlama"
            if not result.get("psychology"):
                result["psychology"] = {"mindset": "Bilinmiyor", "intelligence": "intermediate"}
            if not result.get("next_24h_prediction"):
                result["next_24h_prediction"] = {"action_1": "Privilege escalation attempt", "action_1_tr": "Yetki yükseltme denemesi"}
            if not result.get("confidence"):
                result["confidence"] = 0.7
            if not result.get("reasoning"):
                result["reasoning"] = "Based on command patterns"
            
            return result
            
        except json.JSONDecodeError as e:
            if attempt == 1:
                # Last attempt failed, return default
                return {
                    "type": attacker_type if attacker_type != "unknown" else "opportunistic",
                    "primary_goal": "Reconnaissance and data gathering",
                    "primary_goal_tr": "Sistem keşfi ve veri toplama",
                    "psychology": {"mindset": "Sistematik ve sabırlı", "intelligence": "intermediate"},
                    "next_24h_prediction": {"action_1": "Escalation attempt", "action_1_tr": "Yetki yükseltme"},
                    "confidence": 0.65,
                    "reasoning": f"Analysis based on {len(commands)} commands executed"
                }
        except Exception as e:
            if attempt == 1:
                return {"type": "unknown", "error": str(e), "primary_goal": "?", "primary_goal_tr": "?"}
    
    return {"type": "unknown"}