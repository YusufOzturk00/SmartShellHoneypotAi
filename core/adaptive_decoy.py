import json
import time
import threading
from core.llm_engine import get_ai_response
from core.database import insert_log

class AdaptiveDecoyEngine:
    """Saldirganin davranisina gore dinamik tuzak dosyalar olusturur"""
    
    # Saldirganin ne aradigini anlamak icin pattern'ler
    INTEREST_PATTERNS = {
        "database": [
            "sql", "dump", "backup", "mysql", "postgres", "psql",
            "db", "mongo", "redis", "database", "migration"
        ],
        "credentials": [
            "passwd", "shadow", "password", "credential", "secret",
            "token", "key", "auth", "login", "hash"
        ],
        "crypto_keys": [
            "pem", "key", "rsa", "ssh", "ssl", "cert", "id_rsa",
            "private", "public", "gpg", "pgp"
        ],
        "network": [
            "ifconfig", "ip a", "netstat", "ss ", "arp", "route",
            "hosts", "resolv", "dns", "nmap", "ping"
        ],
        "web": [
            "nginx", "apache", "http", "www", "html", "php",
            "config.php", "wp-config", ".htaccess", "web"
        ],
        "cloud": [
            "aws", "azure", "gcp", "terraform", "docker",
            "kube", "k8s", "cloud", "s3", "ec2", "iam"
        ],
        "source_code": [
            ".py", ".js", ".go", ".java", ".rb", ".sh",
            "git", "repo", "source", "src", "dev"
        ],
        "logs": [
            "log", "syslog", "auth.log", "access.log",
            "error.log", "journal", "audit"
        ]
    }
    
    # Her ilgi alanina gore decoy sablonlari
    DECOY_PROMPTS = {
        "database": """
            The attacker is searching for database files on a Turkish bank server (prod-db-01).
            Generate 3 realistic fake database-related files.
            The bank name is "FinansBank". Use realistic Turkish names and data.
            
            Return ONLY a JSON array:
            [
                {
                    "path": "/full/path/filename.ext",
                    "content": "realistic multi-line content"
                }
            ]
            
            Examples of good paths:
            - /var/backups/finansbank_customers_20240115.sql
            - /opt/db/migration_prod_v2.3.sql
            - /tmp/.db_export_20240114.csv
        """,
        "credentials": """
            The attacker is hunting for credentials on a Turkish bank server (prod-db-01).
            Generate 3 realistic fake credential files.
            Use realistic Turkish names, IPs, services.
            
            Return ONLY a JSON array:
            [
                {
                    "path": "/full/path/filename.ext",
                    "content": "realistic credential content"
                }
            ]
            
            Examples:
            - /home/admin/.pgpass (PostgreSQL credentials)
            - /opt/scripts/.db_creds.conf
            - /var/www/.env.production
        """,
        "crypto_keys": """
            The attacker is searching for SSH/SSL keys on a Turkish bank server.
            Generate 3 realistic fake key files.
            
            Return ONLY a JSON array:
            [
                {
                    "path": "/full/path/filename.ext",
                    "content": "realistic fake key content (NOT real keys)"
                }
            ]
            
            Examples:
            - /home/admin/.ssh/id_rsa_backup_server
            - /opt/ssl/finansbank.com.pem
            - /etc/ssl/private/wildcard.finansbank.local.key
        """,
        "cloud": """
            The attacker is looking for cloud credentials on a Turkish bank server.
            Generate 3 realistic fake cloud config files.
            Use fake but realistic-looking AWS/Azure/GCP credentials.
            
            Return ONLY a JSON array:
            [
                {
                    "path": "/full/path/filename.ext",
                    "content": "realistic cloud config content"
                }
            ]
            
            Examples:
            - /home/admin/.boto (GCP)
            - /opt/terraform/prod.tfvars
            - /root/.config/gcloud/credentials.json
        """,
        "web": """
            The attacker is looking for web application configs on a Turkish bank server.
            Generate 3 realistic fake web config files.
            
            Return ONLY a JSON array:
            [
                {
                    "path": "/full/path/filename.ext",
                    "content": "realistic web config content"
                }
            ]
        """,
        "source_code": """
            The attacker is looking for source code on a Turkish bank server.
            Generate 3 realistic fake source code or config files.
            
            Return ONLY a JSON array:
            [
                {
                    "path": "/full/path/filename.ext",
                    "content": "realistic source code content"
                }
            ]
        """,
        "network": """
            The attacker is performing network reconnaissance on a Turkish bank server.
            Generate 3 realistic fake network config files that would interest them.
            
            Return ONLY a JSON array:
            [
                {
                    "path": "/full/path/filename.ext",
                    "content": "realistic network config"
                }
            ]
        """,
        "logs": """
            The attacker is reading logs on a Turkish bank server.
            Generate 3 realistic fake log files with juicy info.
            
            Return ONLY a JSON array:
            [
                {
                    "path": "/full/path/filename.ext",
                    "content": "realistic log entries"
                }
            ]
        """
    }
    
    def __init__(self):
        self.session_interests = {}  # session_id -> {interest: count}
        self.generated_decoys = {}   # session_id -> [paths]
        self.command_count = {}      # session_id -> int
        self._lock = threading.Lock()
    
    def detect_interest(self, command):
        """Komuttan saldiganin ilgi alanini tespit et"""
        interests = []
        cmd_lower = command.lower()
        
        for category, patterns in self.INTEREST_PATTERNS.items():
            for pattern in patterns:
                if pattern in cmd_lower:
                    interests.append(category)
                    break
        
        return interests if interests else ["general"]
    
    def track_command(self, session_id, command):
        """Her komutu takip et ve ilgi alanlarini guncelle"""
        with self._lock:
            if session_id not in self.session_interests:
                self.session_interests[session_id] = {}
                self.generated_decoys[session_id] = []
                self.command_count[session_id] = 0
            
            self.command_count[session_id] += 1
            
            interests = self.detect_interest(command)
            for interest in interests:
                self.session_interests[session_id][interest] = \
                    self.session_interests[session_id].get(interest, 0) + 1
    
    def should_generate(self, session_id):
        """Her 5 komutta bir decoy uret"""
        count = self.command_count.get(session_id, 0)
        return count > 0 and count % 5 == 0
    
    def get_top_interest(self, session_id):
        """En cok ilgi duyulan kategoriyi bul"""
        interests = self.session_interests.get(session_id, {})
        if not interests:
            return None
        return max(interests, key=interests.get)
    
    def generate_decoys(self, session_id, container, recent_commands):
        """LLM ile yeni tuzak dosyalar uret ve container icinde olustur"""
        top_interest = self.get_top_interest(session_id)
        if not top_interest or top_interest == "general":
            return []
        
        # Daha once uretilmis decoy'lari tekrarlama
        existing = self.generated_decoys.get(session_id, [])
        
        prompt = self.DECOY_PROMPTS.get(top_interest, "")
        if not prompt:
            return []
        
        prompt += f"""
            
            Recent attacker commands: {recent_commands[-10:]}
            Already generated decoys (DO NOT repeat): {existing}
            
            IMPORTANT: Return ONLY valid JSON array. No explanation.
        """
        
        try:
            response = get_ai_response(prompt)
            
            # JSON parse
            response = response.strip()
            if response.startswith("```"):
                response = response.split("\n", 1)[1]
                response = response.rsplit("```", 1)[0]
            
            decoys = json.loads(response)
            
            if not isinstance(decoys, list):
                return []
            
            created = []
            for decoy in decoys[:3]:  # Max 3 dosya
                path = decoy.get("path", "")
                content = decoy.get("content", "")
                
                if not path or not content:
                    continue
                
                # Guvenlik: path traversal engelle
                if ".." in path:
                    continue
                
                # Container icinde dosya olustur
                try:
                    # Dizin olustur
                    dir_path = "/".join(path.split("/")[:-1])
                    if dir_path:
                        container.exec_run(f"mkdir -p {dir_path}")
                    
                    # Dosya yaz (base64 ile guvenli yazim)
                    import base64
                    b64_content = base64.b64encode(content.encode()).decode()
                    container.exec_run(
                        f"/bin/bash -c \"echo {b64_content} | base64 -d > {path}\""
                    )
                    
                    # Dosya tarihini eskiye ayarla (gercekci gozuksun)
                    container.exec_run(
                        f"touch -t 202401{10 + len(created):02d}0830 {path}"
                    )
                    
                    created.append(path)
                    
                except Exception as e:
                    print(f"[DECOY] Dosya olusturma hatasi: {e}")
                    continue
            
            # Kayit tut
            with self._lock:
                self.generated_decoys[session_id].extend(created)
            
            # Logla
            if created:
                insert_log("INFO", f"Adaptive decoys generated: {len(created)}", {
                    "session_id": session_id,
                    "interest": top_interest,
                    "decoys": created,
                    "trigger_commands": recent_commands[-3:]
                })
                
                print(f"[DECOY] \033[35m🎭 {len(created)} yeni tuzak olusturuldu "
                      f"[{top_interest}]: {created}\033[0m")
            
            return created
            
        except json.JSONDecodeError as e:
            print(f"[DECOY] JSON parse hatasi: {e}")
            return []
        except Exception as e:
            print(f"[DECOY] Hata: {e}")
            return []
    
    def cleanup_session(self, session_id):
        """Oturum bitince temizle"""
        with self._lock:
            self.session_interests.pop(session_id, None)
            self.generated_decoys.pop(session_id, None)
            self.command_count.pop(session_id, None)
    
    def get_session_stats(self, session_id):
        """Oturum istatistiklerini don"""
        return {
            "interests": self.session_interests.get(session_id, {}),
            "decoys_generated": len(self.generated_decoys.get(session_id, [])),
            "decoy_paths": self.generated_decoys.get(session_id, []),
            "total_commands": self.command_count.get(session_id, 0)
        }
