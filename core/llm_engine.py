import os
import requests

LLM_API_KEY = os.environ.get("GROQ_API_KEY", "")
LLM_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

def get_ai_response(prompt):
    try:
        resp = requests.post(
            GROQ_URL,
            headers={
                "Authorization": f"Bearer {LLM_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": LLM_MODEL,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 1024,
                "temperature": 0.3,
                "top_p": 0.9,
            },
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"]
        else:
            print(f"[LLM ERROR] Groq {resp.status_code}: {resp.text[:200]}")
    except Exception as e:
        print(f"[LLM ERROR] Groq: {e}")
    return "bash: command not found"
