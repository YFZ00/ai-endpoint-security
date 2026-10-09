\# Demo Scenario



\## Windows Firewall 자동조치 End-to-End Demo



이 문서는 Windows Endpoint에서 의도적으로 보안 설정을 취약하게 만든 뒤,



```text

Detection

→ AI Analysis

→ Action Proposal

→ Harness Validation

→ Human Approval

→ Remediation

→ Verification

→ Audit

```



전체 흐름이 실제로 동작하는지 검증한 시나리오입니다.



\---



\## 1. 테스트 목적



다음 항목을 End-to-End로 검증하는 것이 목적입니다.



```text

1\. Collector가 실제 취약 상태를 수집하는가?

2\. Policy Engine이 FAIL로 판정하는가?

3\. Endpoint Posture에 위험이 반영되는가?

4\. AI Agent가 Read-only Tool을 사용해 상황을 분석하는가?

5\. AI가 등록된 Action만 제안하는가?

6\. Security Harness가 Proposal을 검증하는가?

7\. Human Approval 없이는 실행되지 않는가?

8\. 사전 정의된 Remediation만 실행되는가?

9\. 조치 후 실제 상태를 다시 검증하는가?

10\. 전체 결과가 Audit Log에 남는가?

```



\---



\## 2. 대상 환경



\### Windows Endpoint



```text

Hostname : LAB-WINPC-01

OS       : Microsoft Windows 11 Pro

IP       : 172.30.250.21

```



대상 정책:



```text

WINDOWS-FIREWALL-001

Enable Windows Firewall for all profiles

```



정책 기준:



```text

Expected : true

Severity : HIGH

Comparator: exact

```



\---



\## 3. 취약 상태 생성



테스트를 위해 Windows Firewall의 Domain Profile만 의도적으로 비활성화했습니다.



Private Profile은 유지하여 SSH 관리 연결에는 영향을 주지 않도록 했습니다.



확인 결과:



```text

Name    : Domain

Enabled : False

```



따라서 모든 Firewall Profile이 활성화되어 있어야 한다는 정책을 만족하지 못하는 상태입니다.



\---



\## 4. Policy Evaluation



플랫폼 실행:



```powershell

python main.py --endpoint windows

```



Collector가 Firewall 상태를 수집한 결과:



```text

\[WINDOWS-FIREWALL-001]



Title    : Enable Windows Firewall for all profiles

Expected : true

Actual   : false

Severity : HIGH

Result   : FAIL

```



PASS / FAIL 판정은 AI가 아닌 deterministic Policy Engine에서 수행됩니다.



\---



\## 5. Endpoint Posture



Firewall Finding은 HIGH Severity로 정의되어 있으므로 Posture Score에 반영됩니다.



테스트 당시 결과:



```text

Score        : 88 / 100

Raw Score    : 76 / 100

Risk Level   : MEDIUM

Exceptions   : 1

Failures     : CRITICAL=0 HIGH=1 MEDIUM=0 LOW=0

```



Raw Score에는 다음 두 가지 기술적 위험이 포함되었습니다.



```text

Windows Firewall OFF

→ HIGH

→ -12



BitLocker OFF

→ HIGH

→ -12

```



따라서:



```text

Raw Score

100 - 12 - 12 = 76

```



BitLocker는 승인된 Exception 상태였기 때문에 Effective Score에서는 제외되었습니다.



```text

Effective Score

100 - 12 = 88

```



이를 통해 기술적 위험과 승인된 운영 예외를 분리해서 표현할 수 있습니다.



\---



\## 6. AI Security Agent Investigation



Policy Engine이 FAIL을 생성한 이후 AI Agent가 해당 Finding을 조사합니다.



AI Agent가 호출한 Read-only Tool:



```text

get\_failed\_findings

get\_posture

get\_remediation\_capabilities

```



실제 출력:



```text

Read-only Tools Used :

get\_failed\_findings,

get\_posture,

get\_remediation\_capabilities

```



AI Agent는 Endpoint에 직접 명령을 실행하지 않습니다.



Tool을 통해 현재 상태와 플랫폼에서 허용된 Remediation Capability만 조회합니다.



\---



\## 7. AI Analysis



AI Agent는 Firewall Finding에 대해 다음 항목을 분석했습니다.



```text

Cause

Risk

Recommendation

Operational Impact

```



분석 결과 요약:



```text

Cause

Windows Firewall이 모든 Profile에서 활성화되어 있지 않음



Risk

불필요한 Network Connection 및 외부 접근에 대한 노출 증가



Recommendation

모든 Profile에서 Windows Firewall 활성화



Operational Impact

기존 Inbound Connection이나 애플리케이션 통신에 영향 가능

```



AI는 기존 FAIL 판정을 변경하지 않습니다.



\---



\## 8. Action Proposal



Remediation Capability 조회 결과 해당 Finding에는 다음 Action이 등록되어 있었습니다.



```text

WINDOWS-FIREWALL-001

→ enable\_windows\_firewall

```



AI Agent Proposal:



```text

Finding   : WINDOWS-FIREWALL-001

Action ID : enable\_windows\_firewall

```



AI가 생성하는 것은 Action ID 제안까지입니다.



실제 PowerShell Command는 AI가 생성하지 않습니다.



\---



\## 9. Security Harness Validation



AI Proposal은 바로 실행되지 않고 deterministic Harness에서 다시 검증됩니다.



Harness가 확인하는 조건:



```text

Finding이 현재 FAIL인가?

&#x20;       ↓

자동조치가 등록되어 있는가?

&#x20;       ↓

AI의 Action ID가 등록된 Action과 정확히 일치하는가?

&#x20;       ↓

ALLOW / REJECT

```



실제 결과:



```text

Finding : WINDOWS-FIREWALL-001

Action  : enable\_windows\_firewall

Status  : ALLOW

```



즉 AI의 Proposal이 플랫폼 Allowlist와 정확히 일치함을 확인했습니다.



\---



\## 10. Human Approval



Harness가 ALLOW를 반환해도 자동 실행되지 않습니다.



다음 승인 절차를 거칩니다.



```text

=== Remediation Approval ===



Finding     : WINDOWS-FIREWALL-001

Action ID   : enable\_windows\_firewall

Description : Enable Windows Firewall for all profiles.



Approve remediation? \[y/N]:

```



테스트에서는 운영자가 직접:



```text

y

```



를 입력하여 실행을 승인했습니다.



\---



\## 11. Allowlisted Remediation



승인 이후 애플리케이션에 사전 등록된 Remediation만 실행됩니다.



사용된 Action:



```text

enable\_windows\_firewall

```



Windows Endpoint에서는 보호된 PowerShell Helper가 실행됩니다.



```text

C:\\ProgramData\\AIEndpointSecurity\\

ai-endpoint-remediate.ps1

```



Helper 내부에서 허용된 Action:



```text

enable-firewall-all-profiles

```



실제 실행 결과:



```text

\[INFO] Applying remediation: enable Windows Firewall

\[SUCCESS] All Windows Firewall profiles enabled.

\[SUCCESS] Remediation completed.

```



AI가 생성한 PowerShell 문자열을 실행한 것이 아니라,



```text

AI Action Proposal

&#x20;       ↓

Harness Validation

&#x20;       ↓

Application Allowlist

&#x20;       ↓

Predefined PowerShell Helper

```



구조로 실행했습니다.



\---



\## 12. Verification Scan



Remediation 실행 직후 자동으로 Endpoint를 다시 점검했습니다.



조치 전:



```text

WINDOWS-FIREWALL-001



Expected : true

Actual   : false

Result   : FAIL

```



조치 후:



```text

WINDOWS-FIREWALL-001



Expected : true

Actual   : true

Result   : PASS

```



최종 결과:



```text

All active security policies passed after remediation.

```



즉 단순히 PowerShell Process가 성공한 것으로 조치 완료를 판단한 것이 아니라,



\*\*실제 Endpoint 상태를 다시 수집하고 동일한 Policy로 재평가했습니다.\*\*



\---



\## 13. Audit Logging



조치 과정은 Audit Log에 기록됩니다.



주요 기록 정보:



```text

hostname

platform

finding\_id

before

approved

action\_id

after

verification

policy\_set\_version

source

timestamp

```



해당 테스트의 핵심 기록:



```text

Finding

WINDOWS-FIREWALL-001



Before

false



Approved

true



Action

enable\_windows\_firewall



After

true



Verification

PASS



Policy Version

1.0.0



Source

AI\_AGENT\_HARNESS

```



이를 통해:



```text

누가 승인했는가?

무엇을 조치했는가?

조치 전 상태는 무엇이었는가?

조치 후 실제 상태는 무엇인가?

어떤 Policy Version으로 평가했는가?

```



를 추적할 수 있습니다.



\---



\## 14. End-to-End Flow



전체 Demo 흐름:



```text

Windows Firewall Domain OFF

&#x20;       ↓

Collector

&#x20;       ↓

Actual = false

&#x20;       ↓

Policy Engine

&#x20;       ↓

FAIL

&#x20;       ↓

Posture Score 감소

&#x20;       ↓

AI Agent

&#x20;       ↓

Read-only Tool Calling

&#x20;       ↓

enable\_windows\_firewall 제안

&#x20;       ↓

Security Harness

&#x20;       ↓

ALLOW

&#x20;       ↓

Human Approval

&#x20;       ↓

y

&#x20;       ↓

Allowlisted PowerShell Helper

&#x20;       ↓

Firewall ON

&#x20;       ↓

Verification Scan

&#x20;       ↓

PASS

&#x20;       ↓

Audit Logging

```



\---



\## 15. Demo에서 검증한 핵심 설계



이번 Demo를 통해 다음 사항을 확인했습니다.



\### AI가 보안 판정을 수행하지 않는다



```text

PASS / FAIL

→ Deterministic Policy Engine

```



\### AI가 Endpoint를 직접 변경하지 않는다



```text

AI

→ Analysis

→ Action Proposal

```



까지만 수행합니다.



\### AI Proposal을 신뢰하지 않는다



```text

Proposal

→ Security Harness

→ ALLOW / REJECT

```



\### 사람의 승인이 필요하다



```text

Harness ALLOW

→ Human Approval

→ Execution

```



\### 실제 실행 명령은 사전에 정의되어 있다



```text

AI-generated Command

→ 실행하지 않음



Application Allowlist

→ 실행 가능

```



\### 조치 후 실제 상태를 다시 검증한다



```text

Remediation

→ Re-scan

→ Policy Evaluation

→ PASS

```



\### 전체 과정이 추적 가능하다



```text

Audit Logging

```



\---



\## 16. 결론



이 Demo는 AI가 Endpoint Security 운영을 지원하면서도 실제 시스템 변경 권한은 통제된 영역에 유지할 수 있음을 검증하기 위해 구현했습니다.



핵심 구조는 다음과 같습니다.



```text

AI는 분석하고 제안한다.



Deterministic Harness가 검증한다.



사람이 승인한다.



Allowlist된 코드가 실행한다.



Policy Engine이 실제 조치 결과를 다시 검증한다.

```



이를 통해 AI의 분석 능력을 활용하면서도 보안 운영에 필요한 통제성, 승인 절차, 검증, Audit을 유지하는 구조를 구현했습니다.

