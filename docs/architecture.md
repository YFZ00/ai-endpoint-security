\# Architecture



\## 전체 구조



```mermaid

flowchart TD



&#x20;   WIN\["Windows Endpoint"]

&#x20;   LINUX\["Linux Endpoint"]



&#x20;   COLLECT\["Collectors<br/>Endpoint 보안 상태 수집"]



&#x20;   POLICY\["Deterministic Policy Engine<br/>PASS / FAIL 판정"]



&#x20;   EXCEPTION\["Exception Management<br/>ACTIVE / EXPIRED"]



&#x20;   POSTURE\["Posture Engine<br/>Raw / Effective Score"]



&#x20;   AGENT\["AI Security Agent<br/>분석 및 Action 제안"]



&#x20;   TOOLS\["Read-only Tools<br/>get\_failed\_findings<br/>get\_posture<br/>get\_remediation\_capabilities"]



&#x20;   HARNESS\["Security Harness<br/>Finding 상태 + Allowlist 검증"]



&#x20;   DECISION{"ALLOW / REJECT"}



&#x20;   HUMAN{"Human Approval<br/>y / N"}



&#x20;   REMEDIATION\["Allowlisted Remediation<br/>Predefined Action Only"]



&#x20;   VERIFY\["Verification Scan<br/>재수집 및 정책 재평가"]



&#x20;   AUDIT\["Audit Logging<br/>Before / After / Approval / Verification"]



&#x20;   WIN --> COLLECT

&#x20;   LINUX --> COLLECT



&#x20;   COLLECT --> POLICY

&#x20;   POLICY --> EXCEPTION

&#x20;   EXCEPTION --> POSTURE



&#x20;   POSTURE --> AGENT

&#x20;   AGENT --> TOOLS

&#x20;   TOOLS --> AGENT



&#x20;   AGENT --> HARNESS

&#x20;   HARNESS --> DECISION



&#x20;   DECISION -->|REJECT| AUDIT

&#x20;   DECISION -->|ALLOW| HUMAN



&#x20;   HUMAN -->|Reject| AUDIT

&#x20;   HUMAN -->|Approve| REMEDIATION



&#x20;   REMEDIATION --> VERIFY

&#x20;   VERIFY --> AUDIT

```



\---



\## Trust Boundary



이 프로젝트에서는 \*\*AI와 실제 실행 영역을 분리\*\*하는 것을 핵심 설계 원칙으로 사용했습니다.



```mermaid

flowchart LR



&#x20;   subgraph AI\["Probabilistic / Untrusted 영역"]

&#x20;       AGENT\["AI Security Agent"]

&#x20;       ANALYSIS\["Risk Analysis"]

&#x20;       PROPOSAL\["Action Proposal"]

&#x20;   end



&#x20;   subgraph TRUST\["Deterministic / Trusted 영역"]

&#x20;       POLICY\["Policy Engine"]

&#x20;       HARNESS\["Security Harness"]

&#x20;       HUMAN\["Human Approval"]

&#x20;       ACTION\["Allowlisted Remediation"]

&#x20;       VERIFY\["Verification"]

&#x20;       AUDIT\["Audit"]

&#x20;   end



&#x20;   POLICY --> AGENT

&#x20;   AGENT --> ANALYSIS

&#x20;   ANALYSIS --> PROPOSAL



&#x20;   PROPOSAL --> HARNESS

&#x20;   HARNESS --> HUMAN

&#x20;   HUMAN --> ACTION

&#x20;   ACTION --> VERIFY

&#x20;   VERIFY --> AUDIT

```



AI Agent는 보안 분석과 조치 제안까지만 수행합니다.



실제 Endpoint 변경은 다음 조건을 모두 통과해야 합니다.



```text

1\. 현재 Finding이 FAIL 상태인가?

2\. 해당 Finding에 자동조치가 등록되어 있는가?

3\. AI가 제안한 Action ID가 Allowlist와 정확히 일치하는가?

4\. 운영자가 명시적으로 승인했는가?

```



모든 조건을 만족한 경우에만 사전에 정의된 Remediation Action이 실행됩니다.



\---



\## Component Responsibilities



\### Collector



Linux 및 Windows Endpoint에서 실제 보안 설정값을 수집합니다.



Collector는 판정을 수행하지 않고 \*\*Fact 수집\*\*만 담당합니다.



```text

Collector

→ Actual Value

```



\### Policy Engine



Collector가 수집한 실제 값과 YAML Policy의 기준값을 비교합니다.



```text

Actual

\+

Expected

\+

Comparator

=

PASS / FAIL

```



PASS / FAIL 판정은 AI가 아닌 deterministic code가 수행합니다.



\### Exception Management



FAIL Finding에 승인된 예외가 존재하는지 확인합니다.



```text

FAIL + Active Exception

→ EXEMPT



FAIL + Expired Exception

→ FAIL

```



\### Posture Engine



Endpoint 전체 보안 상태를 점수로 표현합니다.



두 가지 점수를 구분합니다.



```text

Raw Score

→ 실제 기술적 보안 상태



Effective Score

→ 승인된 예외를 반영한 운영 상태

```



\### AI Security Agent



현재 FAIL Finding에 대해서만 분석합니다.



사용 가능한 Tool은 Read-only로 제한됩니다.



```text

get\_failed\_findings

get\_posture

get\_remediation\_capabilities

```



AI는 Shell 또는 PowerShell 실행 권한을 가지고 있지 않습니다.



\### Security Harness



AI가 제안한 Action을 신뢰하지 않고 다시 검증합니다.



```text

AI Proposal

&#x20;   ↓

Finding = FAIL?

&#x20;   ↓

Registered Action?

&#x20;   ↓

Exact Action Mapping?

&#x20;   ↓

ALLOW / REJECT

```



\### Human Approval



Harness에서 ALLOW된 Action도 자동으로 실행하지 않습니다.



```text

Approve remediation? \[y/N]

```



운영자가 승인해야 실제 조치 단계로 넘어갑니다.



\### Remediation



실제 Endpoint 변경은 애플리케이션에 미리 등록된 Action만 사용할 수 있습니다.



AI가 생성한 명령 문자열을 실행하지 않습니다.



\### Verification



Remediation 실행 이후 Endpoint 상태를 다시 수집하고 동일한 정책으로 재평가합니다.



```text

FAIL

→ Remediation

→ Re-scan

→ PASS

```



프로세스가 정상 종료됐다는 사실이 아니라 \*\*실제 보안 상태가 변경됐는지\*\*를 검증합니다.



\### Audit



조치 과정의 주요 정보를 기록합니다.



```text

Finding

Before

Approval

Action

After

Verification

Policy Version

Source

Timestamp

```

