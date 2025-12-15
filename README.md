# linux-ai-host-anomaly

Minimal, IR-focused host triage for Linux systems using AI-assisted analysis.

This project collects high-signal host telemetry from a Linux system and submits it to an AI model to answer one question:

Is there anything suspicious on this host right now?

It is designed for incident response, threat hunting, and first-hour triage — not compliance, asset inventory, or long-term monitoring.

---

DESIGN GOALS

- High signal, low volume
- Fast to run on a live system
- No systemd dependency
- No operator-defined baseline required
- AI infers expected baseline per distro and environment
- Output optimized for IR decision-making

This tool is meant to augment a human IR analyst, not replace one.

---

WHAT IT COLLECTS (HIGH-VALUE ONLY)

The collector intentionally avoids log firehoses and focuses on attacker tradecraft.

Persistence
- System and user cron jobs
- Cron execution targets (path, hash, file head)
- rc.local metadata
- /etc/init.d service inventory

Authentication and Access
- Last successful logins
- Recent failed SSH attempts
- Recent sudo usage
- Risky SSH daemon configuration
- wtmp metadata (anti-forensics check)

Execution
- Root and long-lived processes
- Executables in /tmp and /dev/shm
- Cross-boundary execution (/mnt, /tmp, /dev/shm)

Network Exposure
- Active listening sockets with process context

Privilege
- UID 0 users
- sudoers integrity via file hashes

Software Context
- Package manager type
- Package count
- Service-relevant packages only

---

REPOSITORY STRUCTURE

.
  collect.sh          Host telemetry collector (bash)
  analyze.py          AI analyzer and verdict engine
  requirements.txt    Python dependencies
  .env                Local AI configuration (NOT committed)
  .gitignore
  README.md

---

REQUIREMENTS

System
- Linux (tested on Ubuntu and Debian)
- bash
- jq
- ps, ss, last, grep, awk
- Read access to /var/log/auth.log

Python
- Python 3.9 or newer
- Internet access to OpenAI API

---

SETUP

1. Install Python dependencies

pip3 install -r requirements.txt

2. Create AI configuration file

Create a file named .env in the repository root with the following content:

OPENAI_API_KEY=sk-REPLACE_ME

Optional settings (defaults are fine):

OPENAI_MODEL=gpt-4.1-mini
OPENAI_BASE_URL=https://api.openai.com/v1

---

USAGE

Manual run (recommended for IR triage)

From the repository directory:

bash collect.sh ./host_facts.json
python3 analyze.py ./host_facts.json

The analyzer outputs structured JSON containing:
- A clear suspicious or not verdict
- Confidence score
- Top findings ranked by IR relevance
- Concrete next investigation steps

---

OPERATIONAL NOTES

- Safe to run on live systems
- No system modifications are made
- Data volume is intentionally small
- Output is suitable for tickets or reports
- Collected JSON files contain sensitive host data and must be handled securely

---

LIMITATIONS

- Not a replacement for full forensic acquisition
- Accuracy depends on local log availability
- AI output must always be reviewed by a human analyst

---

INTENDED USE

Intended for:
- Incident responders
- Threat hunters
- SOC escalation triage
- Rapid host suspicion assessment

Not intended for:
- Compliance auditing
- Asset inventory
- Continuous monitoring

---

LICENSE

Use at your own risk. No warranty expressed or implied.
