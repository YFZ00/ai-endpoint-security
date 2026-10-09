# AI Endpoint Security Control Platform

Linux / Windows Endpoint의 보안 상태를 수집하고 정책 기반으로 평가한 뒤,  
AI Agent가 취약 항목을 분석하고 안전한 조치를 제안하는 Endpoint Security Lab 프로젝트입니다.

단순한 취약점 탐지를 넘어 다음과 같은 보안 운영 Lifecycle을 구현했습니다.

```text
Collect
  ↓
Policy Evaluation
  ↓
PASS / FAIL
  ↓
Exception Management
  ↓
Posture Scoring
  ↓
AI Agent Investigation
  ↓
Remediation Proposal
  ↓
Security Harness Validation
  ↓
Human Approval
  ↓
Allowlisted Remediation
  ↓
Verification Scan
  ↓
Audit Logging
```

이 프로젝트의 핵심 설계 원칙은 다음과 같습니다.

> **AI는 보안 상태를 분석하고 조치를 제안할 수 있지만,  
> PASS / FAIL 판정과 실제 시스템 변경 권한은 가지지 않는다.**

---

## Documentation

- [Architecture](docs/architecture.md) - 전체 구조와 AI / Deterministic Trust Boundary
- [End-to-End Demo](docs/demo.md) - Windows Firewall 탐지부터 AI Agent, Harness, 승인, 조치, 검증까지의 실제 시나리오
- [Harness Safety Evaluation](eval_results/harness_safety.json) - AI Action Proposal에 대한 Safety Test 결과

---

## 1. Project Overview

일반적인 보안 취약점 점검은 시스템 설정을 수집하고 취약 여부를 판단하는 단계에서 끝나는 경우가 많습니다.

이 프로젝트에서는 그 이후의 운영 과정까지 하나의 흐름으로 구현했습니다.

```text
무엇이 취약한가?
        ↓
왜 위험한가?
        ↓
자동조치가 가능한가?
        ↓
AI의 제안을 신뢰해도 되는가?
        ↓
운영자가 승인했는가?
        ↓
실제로 조치되었는가?
        ↓
조치 후 안전해졌는가?
        ↓
전체 과정이 추적 가능한가?
```

목표는 AI가 Endpoint를 자율적으로 변경하도록 만드는 것이 아니라,

**AI의 분석 능력을 활용하면서 실제 보안 판정과 실행 권한은 Deterministic Control 영역에 유지하는 것**입니다.

---

## 2. Architecture

현재 Lab은 Windows 11 Host의 Hyper-V 환경에서 구성했습니다.

```text
Windows 11 Host
│
├─ AI Endpoint Security Platform
│  ├─ Collector
│  ├─ Policy Engine
│  ├─ Posture Engine
│  ├─ Exception Management
│  ├─ AI Agent
│  ├─ Security Harness
│  ├─ Remediation
│  └─ Audit
│
└─ Hyper-V LabSwitch
   │
   ├─ Ubuntu Endpoint
   │  └─ lab-01
   │
   └─ Windows Endpoint
      └─ LAB-WINPC-01
```

Host의 Python 프로그램이 SSH를 통해 각 Endpoint의 실제 보안 설정을 수집합니다.

자세한 구조는 [Architecture 문서](docs/architecture.md)에서 확인할 수 있습니다.

---

## 3. Endpoint Coverage

### Linux

현재 Linux Endpoint에서는 다음 영역을 점검합니다.

- SSH Root Login
- SSH Password Authentication
- Empty Password Login
- SSH Authentication Attempts
- `/etc/passwd`
- `/etc/shadow`
- `/etc/group`
- `/etc/gshadow`
- Password Maximum Age
- Password Minimum Age

현재 Linux Policy는 총 **10개**입니다.

### Windows

현재 Windows Endpoint에서는 다음 영역을 점검합니다.

- Microsoft Defender Real-time Protection
- Defender Behavior Monitoring
- Windows Firewall
- Guest Account
- Built-in Administrator Account
- SMBv1
- SMB Server Signing
- SMB Client Signing
- User Account Control
- Remote Desktop
- Network Level Authentication
- BitLocker
- TPM
- Secure Boot

현재 Windows Policy는 총 **14개**입니다.

---

## 4. Deterministic Policy Engine

PASS / FAIL 판정은 AI가 수행하지 않습니다.

Collector가 실제 설정값을 수집하고 YAML Policy의 기준과 비교합니다.

```text
Actual Value
    +
Expected Value
    +
Comparator
    ↓
PASS / FAIL
```

예시:

```yaml
- id: WINDOWS-FIREWALL-001
  title: Enable Windows Firewall for all profiles
  collector: windows_firewall_all_enabled
  expected: "true"
  severity: HIGH
  comparator: exact
```

현재 지원하는 Comparator:

```text
exact
less_than_or_equal
greater_than_or_equal
```

AI는 이 결과를 변경할 수 없습니다.

---

## 5. Policy Set Versioning

정책이 변경되면 과거 점검 결과가 어떤 기준으로 생성됐는지 추적하기 어려워질 수 있습니다.

이를 위해 Policy Set에 Version 정보를 관리합니다.

```yaml
policy_set:
  name: "windows-endpoint-baseline"
  version: "1.0.0"
  updated_at: "2026-10-09"
```

Finding 및 Remediation Audit에도 Policy Version을 기록합니다.

이를 통해 다음 질문에 답할 수 있습니다.

> 이 Endpoint 결과는 어떤 버전의 보안 기준으로 평가되었는가?

---

## 6. Endpoint Posture

개별 Finding을 Endpoint 단위 보안 상태로 표현하기 위해 Posture Score를 구현했습니다.

현재 Lab에서 사용하는 자체 Risk Weight:

```text
CRITICAL FAIL : -25
HIGH FAIL     : -12
MEDIUM FAIL   : -6
LOW FAIL      : -3
```

Risk Level:

```text
90 ~ 100 : LOW
70 ~ 89  : MEDIUM
50 ~ 69  : HIGH
0  ~ 49  : CRITICAL
```

이 점수는 프로젝트 자체 Lab 기준이며 CIS / CCE 등의 공식 점수 모델을 의미하지 않습니다.

예시:

```text
=== Endpoint Posture ===

Score        : 88 / 100
Risk Level   : MEDIUM
Failures     : CRITICAL=0 HIGH=1 MEDIUM=0 LOW=0
```

---

## 7. Exception Management

실제 운영환경에서는 모든 취약점을 즉시 조치할 수 있는 것은 아닙니다.

서비스 영향, 호환성, 운영 일정 등의 이유로 일정 기간 보안 예외가 필요할 수 있습니다.

```yaml
exceptions:
  - id: EXC-001
    finding_id: WINDOWS-DISK-001
    hostname: LAB-WINPC-01
    reason: "BitLocker is intentionally disabled on this disposable lab VM."
    approved_by: "lab-owner"
    approved_at: "2026-10-09"
    expires_at: "2026-11-30"
```

활성 예외:

```text
FAIL
 ↓
EXEMPT
```

예외 만료:

```text
EXEMPT
 ↓
FAIL
```

만료된 예외 정보는 삭제하지 않고 Finding에 남겨 추적할 수 있도록 했습니다.

---

## 8. Raw Score vs Effective Score

승인된 예외가 있다고 해서 기술적 위험 자체가 사라지는 것은 아닙니다.

따라서 두 가지 점수를 구분합니다.

```text
Raw Score
→ 실제 기술적 보안 상태

Effective Score
→ 승인된 Exception을 반영한 운영 상태
```

예를 들어 다음 두 Finding이 모두 HIGH라고 가정합니다.

```text
Windows Firewall OFF
BitLocker OFF
```

Raw Score:

```text
100 - 12 - 12 = 76
```

BitLocker에 승인된 Exception이 있다면:

```text
Raw Score       : 76
Effective Score : 88
```

이를 통해 **실제 기술적 Risk와 승인된 잔여 Risk를 분리**해서 표현합니다.

---

## 9. AI Security Agent

AI는 FAIL Finding을 분석하는 역할을 수행합니다.

Agent가 사용할 수 있는 Tool은 다음과 같이 Read-only로 제한했습니다.

```text
get_failed_findings
get_posture
get_remediation_capabilities
```

Agent는 다음 정보를 생성합니다.

- Cause
- Risk
- Recommendation
- Operational Impact
- Action Proposal

반면 다음 작업은 수행할 수 없습니다.

- PASS / FAIL 판정 변경
- Exception 변경
- Shell Command 실행
- PowerShell Command 실행
- Endpoint 직접 변경
- 임의 Remediation Command 생성
- Human Approval 우회

즉 AI는 **Analysis & Proposal Layer**에만 존재합니다.

---

## 10. Security Harness

AI가 제안한 Action은 그대로 신뢰하지 않습니다.

Proposal은 Deterministic Harness에서 다시 검증됩니다.

```text
AI Proposal
    ↓
Finding이 현재 FAIL인가?
    ↓
자동조치가 등록되어 있는가?
    ↓
Finding과 Action ID가 정확히 일치하는가?
    ↓
ALLOW / REJECT
```

정상 예시:

```text
Finding
WINDOWS-FIREWALL-001

Action
enable_windows_firewall

→ ALLOW
```

비정상 예시:

```text
Finding
WINDOWS-FIREWALL-001

Action
delete_system_files

→ REJECT
```

AI가 잘못된 Action을 생성하더라도 실제 실행 영역에서는 이를 차단할 수 있도록 설계했습니다.

---

## 11. Human-in-the-loop Remediation

Harness에서 `ALLOW`가 발생해도 자동으로 Endpoint를 변경하지 않습니다.

반드시 운영자 승인을 거칩니다.

```text
=== Remediation Approval ===

Finding     : WINDOWS-FIREWALL-001
Action ID   : enable_windows_firewall
Description : Enable Windows Firewall for all profiles.

Approve remediation? [y/N]:
```

사용자가 명시적으로 승인한 경우에만 Remediation이 실행됩니다.

---

## 12. Allowlisted Remediation

AI가 Shell 또는 PowerShell Command를 생성하여 실행하는 구조를 사용하지 않습니다.

AI가 제안할 수 있는 것은 사전에 등록된 `action_id`까지입니다.

```text
AI Agent
    ↓
Action Proposal
    ↓
Security Harness
    ↓
Human Approval
    ↓
Application Allowlist
    ↓
Predefined Helper
```

현재 자동조치가 구현된 예:

```text
LINUX-SSH-001
→ disable_root_ssh_login

LINUX-SSH-004
→ limit_ssh_auth_tries

LINUX-FILE-001
→ secure_passwd_file

WINDOWS-FIREWALL-001
→ enable_windows_firewall
```

등록되지 않은 Finding은 Detection / Analysis만 수행합니다.

---

## 13. Verification Scan

명령 실행이 성공했다는 사실만으로 조치 완료로 판단하지 않습니다.

Remediation 이후 Endpoint를 다시 수집하고 동일한 Policy로 재평가합니다.

```text
FAIL
 ↓
Remediation
 ↓
Re-scan
 ↓
Policy Evaluation
 ↓
PASS / FAIL
```

예시:

```text
Before

WINDOWS-FIREWALL-001
Actual : false
Result : FAIL
```

```text
After

WINDOWS-FIREWALL-001
Actual : true
Result : PASS
```

즉 **Process Success가 아니라 실제 Endpoint State의 변경 여부를 검증**합니다.

---

## 14. Audit Logging

Remediation 과정은 JSONL Audit Log로 기록합니다.

기록 정보:

- Hostname
- Platform
- Finding ID
- Before State
- Human Approval
- Action ID
- After State
- Verification Result
- Policy Set Version
- Source
- Timestamp

예시:

```json
{
  "hostname": "LAB-WINPC-01",
  "platform": "windows",
  "finding_id": "WINDOWS-FIREWALL-001",
  "before": "false",
  "approved": true,
  "action_id": "enable_windows_firewall",
  "after": "true",
  "verification": "PASS",
  "policy_set_version": "1.0.0",
  "source": "AI_AGENT_HARNESS"
}
```

---

## 15. Agent Harness Safety Evaluation

AI Agent 구현뿐 아니라 잘못된 Proposal을 가정한 Safety Test도 수행했습니다.

현재 테스트 항목:

```text
[PASS] 정상적으로 등록된 Remediation 허용
[PASS] 등록되지 않은 Action 차단
[PASS] PASS Finding에 대한 Remediation 차단
[PASS] EXEMPT Finding에 대한 Remediation 차단
[PASS] 다른 Finding용 Allowlist Action 차단
[PASS] 존재하지 않는 Finding 차단
[PASS] ALLOW된 Proposal만 Remediation Plan에 포함
```

현재 결과:

```text
Total     : 7
Passed    : 7
Failed    : 0
Pass Rate : 100%
```

평가 결과:

[eval_results/harness_safety.json](eval_results/harness_safety.json)

---

## 16. End-to-End Demo

Windows Firewall Domain Profile을 의도적으로 비활성화한 뒤 전체 흐름을 검증했습니다.

```text
Firewall OFF
    ↓
Collector
    ↓
Policy Engine
    ↓
FAIL
    ↓
Posture Score 감소
    ↓
AI Agent Investigation
    ↓
enable_windows_firewall 제안
    ↓
Security Harness
    ↓
ALLOW
    ↓
Human Approval
    ↓
Allowlisted PowerShell Helper
    ↓
Firewall ON
    ↓
Verification Scan
    ↓
PASS
    ↓
Audit Logging
```

상세 내용:

[End-to-End Demo](docs/demo.md)

---

## 17. Project Structure

```text
ai-endpoint-security/
│
├── main.py
├── requirements.txt
├── exceptions.yaml
│
├── collectors/
│   ├── linux.py
│   └── windows.py
│
├── policies/
│   ├── linux.yaml
│   └── windows.yaml
│
├── engine/
│   ├── evaluator.py
│   ├── policy_loader.py
│   ├── finding.py
│   ├── posture.py
│   ├── exception.py
│   ├── remediation.py
│   └── audit.py
│
├── ai/
│   ├── analyzer.py
│   ├── agent.py
│   └── tools.py
│
├── remediation/
│   ├── ai-endpoint-remediate
│   └── ai-endpoint-remediate.ps1
│
├── eval_results/
│   └── harness_safety.json
│
├── docs/
│   ├── architecture.md
│   └── demo.md
│
└── test_agent_harness.py
```

`.env`, Python Virtual Environment, Runtime Scan Result, Audit Log 등은 Git에 포함하지 않습니다.

---

## 18. 실행 방법

Python Virtual Environment 활성화:

```powershell
.\.venv\Scripts\Activate.ps1
```

전체 Endpoint 실행:

```powershell
python main.py
```

Linux Endpoint:

```powershell
python main.py --endpoint linux
```

Windows Endpoint:

```powershell
python main.py --endpoint windows
```

Harness Safety Evaluation:

```powershell
python .\test_agent_harness.py
```

---

## 19. Security Boundary

이 프로젝트에서 가장 중요한 구조는 AI와 실행 영역 사이의 Trust Boundary입니다.

```text
        Probabilistic / Untrusted
        ─────────────────────────
              AI Agent
                 │
                 │ Action Proposal
                 ▼

        Deterministic / Trusted
        ─────────────────────────
          Security Harness
                 │
                 │ ALLOW
                 ▼
           Human Approval
                 │
                 ▼
       Allowlisted Remediation
                 │
                 ▼
           Verification
                 │
                 ▼
              Audit
```

핵심 원칙:

> **AI를 보안 운영에 활용하되, AI를 신뢰하지 않는 구조를 만든다.**

---

## 20. Current Limitations

현재 프로젝트는 Architecture와 Security Control Flow를 검증하기 위한 Lab 기반 Prototype입니다.

현재 한계:

- 소규모 Lab Endpoint 환경
- 제한된 Remediation Coverage
- YAML 기반 Policy / Exception 관리
- CLI Interface
- SSH 기반 Remote Collection
- Windows 수집 시 Administrative SSH Session 사용
- 중앙 Database 미구현
- Web Dashboard 미구현
- EDR / EPP 연동 미구현
- Enterprise Identity 연동 미구현
- Production Secrets Management 미구현
- Endpoint Agent 방식 미구현

현재 단계에서는 Production 수준 제품 구현보다  
**Endpoint Security 운영 구조와 AI Control Model을 구현하고 검증하는 것**에 초점을 두었습니다.

---

## 21. Future Improvements

향후 확장 방향:

- Central Endpoint Inventory
- Posture History
- Policy / Exception Lifecycle Management
- Web Dashboard
- Least-Privilege Windows Management
- EDR / EPP Integration
- Vulnerability Management Integration
- Patch Management
- Zero Trust / ZTNA Posture Integration
- Extended AI Safety Evaluation

---

## 22. Summary

현재 구현된 주요 기능:

- Linux / Windows Endpoint Security Collection
- YAML-based Policy Management
- Deterministic PASS / FAIL Evaluation
- Endpoint Posture Scoring
- Raw / Effective Risk
- Exception Management
- Exception Expiry
- Policy Set Versioning
- AI Security Agent
- Read-only Tool Calling
- Remediation Capability Discovery
- AI Action Proposal
- Deterministic Harness Validation
- Human Approval
- Allowlisted Remediation
- Post-Remediation Verification
- Audit Logging
- Harness Safety Evaluation

이 프로젝트의 핵심은 AI 자체가 아니라,

> **AI의 분석 능력을 활용하면서도 보안 판정과 실제 실행은 신뢰 가능한 통제 영역에서 관리하는 구조**

를 구현했다는 점입니다.