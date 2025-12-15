#!/usr/bin/env python3
import sys
import json
import os
from datetime import datetime
from dotenv import load_dotenv
from openai import OpenAI

# ---------------- CONFIG ----------------

MAX_CHARS = 6000

load_dotenv()

API_KEY = os.getenv("OPENAI_API_KEY")
MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"

if not API_KEY and not DRY_RUN:
    print("[ERROR] OPENAI_API_KEY not set", file=sys.stderr)
    sys.exit(1)

client = None
if not DRY_RUN:
    client = OpenAI(api_key=API_KEY)

# ---------------- HELPERS ----------------

def die(msg):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)

def chunk_text(label, text):
    chunks = []
    current = ""
    for line in text.splitlines():
        if len(current) + len(line) > MAX_CHARS:
            chunks.append(current)
            current = ""
        current += line + "\n"
    if current.strip():
        chunks.append(current)
    return [(label, i + 1, c) for i, c in enumerate(chunks)]

# ---------------- LOAD FACTS ----------------

if len(sys.argv) != 2:
    die("usage: analyze.py <facts.json>")

facts_path = sys.argv[1]

try:
    with open(facts_path, "r") as f:
        facts = json.load(f)
except Exception as e:
    die(f"failed to load facts: {e}")

# ---------------- SUMMARIZE ----------------

summary = {
    "collected_at": facts.get("collected_at"),
    "os": facts.get("os_release", "").splitlines()[:3],
    "kernel": facts.get("kernel"),
    "uptime_seconds": facts.get("uptime_seconds"),
    "package_manager": facts.get("packages", {}).get("mode"),
    "package_count": facts.get("packages", {}).get("count"),
    "serviceish_packages": facts.get("packages", {}).get("serviceish", "").splitlines(),
    "listeners": facts.get("listeners", "").splitlines(),
    "uid0_users": facts.get("privilege", {}).get("uid0_users"),
    "initd_services": facts.get("persistence", {}).get("initd_list", "").splitlines(),
}

processes = facts.get("processes", "")
etc_cron = facts.get("persistence", {}).get("etc_cron", "")
user_cron = facts.get("persistence", {}).get("user_cron", "")
tmp_execs = facts.get("suspicious_artifacts", {}).get("tmp_execs", "")

# ---------------- SYSTEM PROMPT ----------------

SYSTEM_PROMPT = f"""
You are a senior Linux intrusion analyst.

Task:
- Infer the most likely NORMAL baseline for this system
- Identify deviations, suspicious artifacts, or misconfigurations
- Assume you are seeing this system for the FIRST TIME

Rules:
- Do NOT assume observed state is benign
- Use distro, packages, listeners, and persistence to infer intent
- If something could be normal depending on role, say what role
- Focus on persistence, privilege, and exposure

Output STRICTLY as valid JSON.
- No markdown
- No prose
- No explanations outside JSON
- If uncertain, state uncertainty INSIDE JSON fields

Output schema:
{{
  "inferred_role": "...",
  "baseline_assumptions": ["..."],
  "findings": [
    {{
      "severity": "low|medium|high",
      "evidence": "...",
      "reasoning": "...",
      "recommended_next_step": "..."
    }}
  ]
}}

Timestamp: {datetime.utcnow().isoformat()}Z
""".strip()

# ---------------- BUILD MESSAGES ----------------

messages = [
    {
        "role": "system",
        "content": SYSTEM_PROMPT
    }
]

messages.append({
    "role": "user",
    "content": "### SYSTEM_SUMMARY\n" + json.dumps(summary, indent=2)
})

if processes.strip():
    for label, idx, content in chunk_text("PROCESSES", processes):
        messages.append({
            "role": "user",
            "content": f"### {label} (chunk {idx})\n{content}"
        })

if summary["listeners"]:
    messages.append({
        "role": "user",
        "content": "### LISTENERS\n" + "\n".join(summary["listeners"])
    })

if etc_cron.strip():
    for label, idx, content in chunk_text("SYSTEM_CRON", etc_cron):
        messages.append({
            "role": "user",
            "content": f"### {label} (chunk {idx})\n{content}"
        })

if user_cron.strip():
    for label, idx, content in chunk_text("USER_CRON", user_cron):
        messages.append({
            "role": "user",
            "content": f"### {label} (chunk {idx})\n{content}"
        })

if tmp_execs.strip():
    for label, idx, content in chunk_text("TMP_AND_SHM_ARTIFACTS", tmp_execs):
        messages.append({
            "role": "user",
            "content": f"### {label} (chunk {idx})\n{content}"
        })

# ---------------- DRY RUN ----------------

if DRY_RUN:
    print("=== DRY RUN: PROMPT ===\n")
    for m in messages:
        print(f"[{m['role'].upper()}]\n{m['content']}\n")
    sys.exit(0)

# ---------------- OPENAI CALL ----------------

response = client.responses.create(
    model=MODEL,
    input=messages,
)

# ---------------- PARSE OUTPUT ----------------

raw = response.output_text.strip()

try:
    parsed = json.loads(raw)
except json.JSONDecodeError:
    print("[ERROR] Model did not return valid JSON", file=sys.stderr)
    print(raw)
    sys.exit(2)

print(json.dumps(parsed, indent=2))
