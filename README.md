\# AI Endpoint Security Control Platform



A security engineering lab project that combines deterministic endpoint security controls with an AI agent, human approval, allowlisted remediation, posture scoring, exception management, verification, audit logging, and safety evaluations.



The project is designed around one core principle:



> \*\*AI can analyze and propose actions, but it must not directly decide security compliance or execute arbitrary commands.\*\*



\---


## Documentation

- [Architecture](docs/architecture.md) - 전체 구조와 AI / Deterministic Trust Boundary
- [End-to-End Demo](docs/demo.md) - Windows Firewall 탐지부터 AI Agent, Harness, 승인, 조치, 검증까지의 실제 시나리오


\## 1. Project Overview


Traditional endpoint security assessment tools often stop at identifying insecure configurations.



This project extends that workflow into a controlled security operations pipeline:



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

Deterministic Harness Validation

 ↓

Human Approval

 ↓

Allowlisted Remediation

 ↓

Verification Scan

 ↓

Audit Logging

