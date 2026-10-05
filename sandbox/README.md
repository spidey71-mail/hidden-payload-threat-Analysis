# Isolated Payload Analysis Sandbox

## Overview

The Isolated Payload Analysis Sandbox is a security-focused execution environment designed for the hidden-payload threat analysis project.

The sandbox provides an isolated environment for analyzing files recovered from potentially steganographic images. The initial version deliberately focuses on **static analysis** and does not execute untrusted payloads.

The goal of this component is to establish a controlled analysis boundary before integrating steganalysis, payload extraction, malware classification, QLoRA-based security interpretation, and LLM-driven orchestration.

---

## Current Version

**Sandbox v0.1 — Static Analysis Isolation**

### Current capabilities

- Docker-based isolated analysis environment
- Non-root execution
- Read-only container filesystem
- Disabled network access
- Linux capabilities dropped
- Privilege escalation disabled
- CPU resource limitation
- Memory limitation
- Process limitation
- Read-only input mount
- Controlled output mount
- SHA-256 file hashing
- Shannon entropy calculation
- Printable string extraction
- JSON evidence generation
- Disposable analysis containers

---

## Architecture

```text
                         INPUT FILE
                             │
                             ▼
                       QUARANTINE
                             │
                             ▼
                 ┌──────────────────────┐
                 │   Docker Sandbox     │
                 │                      │
                 │  Non-root user       │
                 │  Read-only FS        │
                 │  No network          │
                 │  No capabilities     │
                 │  Resource limits     │
                 └──────────┬───────────┘
                            │
                            ▼
                    STATIC ANALYSIS
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
           SHA-256       Entropy       Strings
              │             │             │
              └─────────────┼─────────────┘
                            ▼
                       report.json
```

---

## Directory Structure

```text
sandbox/
│
├── Dockerfile
├── docker-compose.yml
├── README.md
│
├── analyzer/
│   ├── analyzer.py
│   └── requirements.txt
│
├── input/
│   └── sample.txt
│
├── output/
│
└── rules/
```

### Components

| Component | Purpose |
|---|---|
| `Dockerfile` | Builds the isolated analysis image |
| `docker-compose.yml` | Defines sandbox security and resource restrictions |
| `analyzer/analyzer.py` | Performs static file analysis |
| `analyzer/requirements.txt` | Python dependencies |
| `input/` | Read-only analysis input |
| `output/` | Generated analysis reports |
| `rules/` | Reserved for future YARA/security rules |

---

## Security Controls

The sandbox currently applies the following controls:

### Non-root execution

The analyzer runs using a dedicated unprivileged user:

```dockerfile
USER analyzer
```

### Read-only filesystem

The container root filesystem is mounted read-only:

```yaml
read_only: true
```

### Network isolation

The sandbox has no network access:

```yaml
network_mode: "none"
```

### Linux capability restriction

All Linux capabilities are removed:

```yaml
cap_drop:
  - ALL
```

### Privilege escalation prevention

```yaml
security_opt:
  - no-new-privileges:true
```

### Resource restrictions

```yaml
pids_limit: 128
mem_limit: 1g
cpus: 1.0
```

### Controlled file access

Input files are mounted read-only:

```yaml
- ./input:/sandbox/input:ro
```

Analysis results are written to a controlled output directory:

```yaml
- ./output:/sandbox/output:rw
```

---

## Static Analysis

The current analyzer collects:

### File metadata

- File name
- File size
- SHA-256 hash

### Statistical characteristics

- Shannon entropy

### Content indicators

- Printable strings

### Execution state

The generated report explicitly records:

```json
{
  "analysis_mode": "static",
  "executed": false,
  "network_access": false
}
```

This is intentional. **Sandbox v0.1 does not execute analyzed files.**

---

## Running the Sandbox

From the `sandbox` directory:

### Build

```bash
docker compose build
```

### Run analysis

```bash
docker compose run --rm analyzer
```

The `--rm` option removes the temporary analysis container after execution.

### View the generated report

PowerShell:

```powershell
Get-Content output\report.json
```

---

## Current Validation

The Docker image has been successfully built using:

```bash
docker compose build
```

The successful build verifies that:

- The Python base image can be obtained.
- The Dockerfile is valid.
- The analyzer dependencies can be installed.
- The analyzer source is copied into the image.
- The non-root analysis user is created.
- The sandbox directories are created.
- The Docker image can be generated successfully.

The next validation stage is to execute the analyzer against a harmless test file and verify the generated evidence report.

---

## Research Role

The sandbox is a foundational component of the proposed hidden-payload threat analysis architecture.

The planned end-to-end pipeline is:

```text
Image
  │
  ▼
AI Steganalysis
  │
  ▼
Hidden Payload Detection
  │
  ▼
Payload Extraction
  │
  ▼
Quarantine
  │
  ▼
Isolated Sandbox
  │
  ▼
Static / Controlled Analysis
  │
  ▼
Security Evidence
  │
  ▼
QLoRA Security Analyst
  │
  ▼
LLM Orchestrator
  │
  ▼
Threat Assessment
```

The LLM orchestrator will eventually determine which analysis tools should be invoked based on the current evidence.

---

## Planned Extensions

Future versions may include:

- YARA rule scanning
- File-type identification
- PE analysis
- ELF analysis
- Archive inspection
- Suspicious API/import analysis
- Advanced entropy analysis
- Payload feature extraction
- EMBER-compatible security representations
- Automated evidence normalization
- Sandbox manager API
- Agent-controlled tool selection
- Controlled dynamic analysis using a stronger isolation boundary

### Dynamic Analysis Note

Docker is being used as the initial development and static-analysis isolation layer.

Docker containers should **not** be treated as an absolute security boundary for executing arbitrary real-world malware. If dynamic execution of genuinely malicious samples becomes necessary, the execution layer will be moved to a disposable VM-based environment with stronger isolation and controlled networking.

---

## Milestone

### Sandbox v0.1 — Static Isolation

**Status: Docker image successfully built**

Completed:

- [x] Project structure
- [x] Dockerfile
- [x] Docker Compose configuration
- [x] Non-root analyzer
- [x] Network isolation configuration
- [x] Capability restrictions
- [x] Resource restrictions
- [x] Static analyzer
- [x] JSON evidence pipeline
- [x] Successful Docker image build

Next:

- [ ] Execute harmless sample
- [ ] Verify generated report
- [ ] Verify security configuration
- [ ] Add YARA
- [ ] Add file identification
- [ ] Add PE/ELF analysis
- [ ] Integrate payload feature extraction
- [ ] Integrate orchestration layer

---

## Safety Principle

The sandbox follows a simple principle:

> **Untrusted content should be analyzed inside an isolated environment rather than trusted by default.**

The project will progressively strengthen this boundary as dynamic analysis capabilities are introduced.

//## Static Detector v0.2

The sandbox was extended with a static artifact detection layer. The detector analyzes files without executing them and extracts potentially relevant indicators for downstream payload classification.

### Static Analysis Capabilities

The current analyzer extracts:

- SHA-256 file hashes
- File size
- Shannon entropy
- Printable strings
- Known file signatures
- URLs
- Command/interpreter indicators
- Base64-encoded candidates
- Hexadecimal candidates

The detector currently recognizes common signatures including:

- PE / Windows executable
- ELF executable
- PDF
- ZIP/archive
- PNG
- JPEG
- GIF

Command indicators currently include:

- PowerShell
- CMD
- Bash
- `/bin/sh`

### Controlled Validation Corpus

A controlled benign test corpus was created to verify each detector independently.

| Artifact | Purpose | Expected Detection | Result |
|---|---|---|---|
| `sample.txt` | Benign text | No indicators | PASS |
| `fake_pe.bin` | PE magic-byte test | PE signature | PASS |
| `encoded.txt` | Encoding test | Base64 candidate | PASS |
| `url_test.txt` | Network indicator test | URL | PASS |
| `command_test.txt` | Command indicator test | PowerShell | PASS |

### Validation Output

The analyzer successfully produced structured JSON containing the extracted static indicators.

Example:

```json
{
  "file_name": "command_test.txt",
  "analysis_mode": "static",
  "executed": false,
  "network_access": false,
  "static_indicators": {
    "file_signatures": [],
    "urls": [],
    "command_indicators": [
      "powershell"
    ],
    "base64_candidates": [],
    "hex_candidates": []
  }
}