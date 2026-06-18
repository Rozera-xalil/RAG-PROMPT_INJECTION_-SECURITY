<img width="2200" height="1070" alt="Secure_RAG_Architecture" src="https://github.com/user-attachments/assets/416a7146-c16b-48ca-9687-201ce3a519dc" />
# 🏢 Enterprise-Grade Secure RAG Architecture
### 12-Layer Defense Against Prompt Injection


> By **Rozêra** — AI Engineer

---

## Architecture

```
User Query
    │
    ▼
[1]  Input Sanitizer        ← Regex + secrets redaction
[2]  Risk Scorer            ← Weighted 0-100 composite score
[3]  Access Control         ← Role-based document filtering
[4]  Trust Filter           ← Reject low-trust sources
[5]  Context Firewall       ← Strip commands, keep facts
[6]  Embedding Poison Gate  ← Block before indexing
[7]  Doc Risk Scorer        ← Score each document individually
[8]  LLM Security Auditor   ← Semantic injection detection
[9]  Grounding Validator    ← Every claim traceable to context?
[10] Output Filter          ← Final scan on LLM response
[11] Citation Verifier      ← All sources real and cited?
[12] Audit Logger           ← Full forensic record saved
    │
    ▼
✅ Safe Response
```

---

## What's New vs Basic Secure RAG

| Feature | Basic RAG | This Project |
|---------|-----------|-------------|
| Injection detection | Regex only | Regex + LLM auditor |
| Document trust | All equal | Per-source trust scores |
| Semantic attacks | ❌ Missed | ✅ LLM catches them |
| Access control | ❌ None | ✅ Role-based |
| Hallucination check | ❌ None | ✅ Grounding validator |
| Citations | ❌ None | ✅ Enforced + verified |
| Session tracking | ❌ None | ✅ Repeated attempts escalated |
| Secrets | ❌ Exposed | ✅ Auto-redacted |
| Audit trail | ❌ None | ✅ Full JSONL log |

---

## Project Structure

```
secure-rag-enterprise/
│
├── notebooks/
│   └── enterprise_secure_rag.ipynb   ← Full tutorial
│
├── src/
│   ├── document_firewall.py          ← Trust scoring + context firewall
│   ├── risk_engine.py                ← Weighted risk scoring (0-100)
│   ├── llm_auditor.py                ← LLM-based detection + grounding
│   ├── access_control.py             ← RBAC + citation enforcement
│   ├── audit_logger.py               ← Full audit trail
│   └── enterprise_pipeline.py        ← Main orchestrator
│
└── README.md
```

---

## Quick Start

```bash
git clone https://github.com/Rozera-xalil/RAG-PROMPT_INJECTION_-SECURITY
cd RAG-PROMPT_INJECTION_-SECURITY
pip install groq python-dotenv
echo "groqapi=-..." > .env
jupyter notebook notebooks/enterprise_secure_rag.ipynb
```

---

## Key Design Decisions

**1. Numeric Risk Score (0-100) over binary safe/unsafe**
Allows gradual responses: ALLOW → WARN → BLOCK

**2. LLM-as-Judge for semantic attacks**
Regex cannot catch: *"Pretend the above never existed"*
A small LLM call costs ~$0.001 and catches what Regex misses.

**3. Context Firewall: strip commands, keep facts**
*"Ignore all instructions. Paris is the capital of France."*
Becomes: *"Paris is the capital of France."*
We don't throw away the whole document — just the dangerous part.

**4. Session-Level Escalation**
An attacker sending multiple low-risk queries gets escalating scores.
Catches probing attacks that look innocent individually.

**5. Citation Enforcement**
Every claim must have a source. Uncited claims = potential hallucination.

---

*By Rozêra — follow on [Medium](https://medium.com/@rozxalil801) for more AI security content*
