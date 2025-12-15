# HostTriageAI

**AI-assisted Linux host triage using high-signal telemetry**

HostTriageAI collects **high-value, low-volume host data** from a Linux system and submits it to an AI model to answer a single operational question:

> **Is there anything suspicious on this host right now?**

It is designed for **incident response, threat hunting, and first-look triage**, not compliance scanning, asset inventory, or generic hardening guidance.

---

## How it works (high level)

```mermaid
flowchart TD
    A[Linux Host Snapshot] --> B[High-Signal Collection]

    B --> B1[Processes<br/>(root + long-lived)]
    B --> B2[Network Exposure<br/>(listeners)]
    B --> B3[Persistence<br/>(cron, init.d, rc.local)]
    B --> B4[Authentication<br/>(SSH success & failure)]
    B --> B5[Artifacts<br/>(/tmp, /dev/shm executables)]
    B --> B6[Privilege<br/>(uid0, sudoers, SSH keys)]

    B --> C[Normalization & Chunking]

    C --> D[AI Analysis Engine]

    D --> D1[Infer likely baseline]
    D --> D2[Detect deviations]
    D --> D3[Assess persistence & exposure]

    D --> E[Verdict + Findings (JSON)]

    E --> E1[Is host suspicious?]
    E --> E2[Evidence]
    E --> E3[Reasoning]
    E --> E4[Actionable next steps]
```

The diagram is text-native, dark-mode safe, and intentionally minimal to avoid visual noise.

---

## Design goals

- **High signal, low volume**  
  No full filesystem walks, no “collect everything and hope.”

- **IR-first thinking**  
  Persistence, authentication, execution, privilege, and exposure take priority.

- **Baseline inferred, not assumed**  
  The AI infers what “normal” should look like for the host instead of trusting the current state.

- **Human-verifiable output**  
  Every finding includes concrete evidence and explicit follow-up actions.

- **Theme-safe documentation**  
  No raster images, no fixed colors, no margin or clipping issues.

---

## What is collected (intentionally limited)

### Execution & runtime
- Root processes
- Long-lived processes
- Network listeners with process context

### Persistence
- System cron (`/etc/crontab`, `/etc/cron.*`)
- User crontabs
- `init.d` scripts
- `rc.local`
- Cron-executed script inspection (path, owner, hash, header)

### Authentication & access (IR-grade)
- Last successful logins
- Failed authentication attempts
- Successful SSH logins
- Current interactive sessions (`who`, `w`)
- SSH daemon authentication configuration
- Authorized SSH keys (hash + header only)

### Privilege
- UID 0 accounts
- Sudoers files (hash only)

### Artifacts
- Executable files in `/tmp` and `/dev/shm`
- Suspicious writable locations commonly abused for staging

---

## What this tool is not

- Not a compliance scanner  
- Not a vulnerability scanner  
- Not a full EDR replacement  
- Not a “trust the host” auditor  

HostTriageAI assumes the host **may already be compromised**.

---

## Output

The analyzer produces **structured JSON**, designed for both humans and automation:

```json
{
  "verdict": {
    "suspicious": true,
    "confidence": 78,
    "why": "Persistent cron execution from a cross-filesystem path"
  },
  "top_findings": [
    {
      "severity": "high",
      "category": "persistence",
      "evidence": "Cron job executes /mnt/e/fetch_news_vector.py",
      "why_suspicious": "Persistence via cross-OS trust boundary",
      "most_likely_benign": "User automation task",
      "what_to_do_next": [
        "sha256sum /mnt/e/fetch_news_vector.py",
        "review script contents",
        "confirm business justification"
      ]
    }
  ]
}
```

---

## Intended use cases

- Incident response triage
- Threat hunting
- Suspicious host validation
- Cloud and ephemeral host inspection
- WSL and developer workstation abuse detection

---

## Philosophy

> **Don’t collect everything. Collect what attackers can’t hide.**

HostTriageAI is built to surface meaningful deviations, not drown analysts in data.
