"""
enterprise_pipeline.py
-----------------------
THE MAIN PIPELINE — orchestrates all security layers in order.

Full Architecture:
  User Query
      │
      ▼
  [1] Input Sanitizer       ← Regex + secrets redaction
      │
      ▼
  [2] Risk Scorer           ← Weighted scoring engine
      │
      ▼
  [3] Access Control        ← Role-based document filtering
      │
      ▼
  [4] Trust Filter          ← Reject low-trust sources
      │
      ▼
  [5] Context Firewall      ← Strip commands, keep facts
      │
      ▼
  [6] Embedding Poison Gate ← Block before indexing
      │
      ▼
  [7] LLM Security Auditor  ← Semantic injection detection
      │
      ▼
  [8] Prompt Builder        ← Hardened + cited prompt
      │
      ▼
      LLM generates answer
      │
      ▼
  [9] Grounding Validator   ← Every claim in context?
      │
      ▼
  [10] Output Filter        ← Final Regex check on response
      │
      ▼
  [11] Citation Verifier    ← All sources real and cited?
      │
      ▼
  [12] Audit Logger         ← Full record saved
      │
      ▼
  ✅ Safe Response
"""

import os
import re
from groq import Groq

from document_firewall import (
    Document,
    assign_trust_score,
    filter_by_trust,
    apply_context_firewall,
    validate_before_indexing,
)
from risk_engine       import score_text, score_documents
from llm_auditor       import llm_detect_injection, validate_grounding, redact_secrets, audit_documents
from access_control    import UserContext, filter_by_access, build_cited_prompt, verify_citations
from audit_logger      import AuditRecord, write_audit_log

client = Groq(api_key="")

GENERATION_MODEL = "llama-3.3-70b-versatile"

# ─────────────────────────────────────────────────
# Output Filter (Layer 10)
# ─────────────────────────────────────────────────

OUTPUT_DANGER_PATTERNS = [
    r"^HACKED",
    r"I am now DAN",
    r"I have no (restrictions|limitations)",
    r"I will (now )?ignore (my )?(guidelines|rules|instructions)",
    r"sending .{0,30} to .{0,50}\.(com|io|net)",
    r"developer mode (activated|enabled)",
    r"all (previous )?user (queries|data|history)",
    r"revealing (system|config|prompt|password)",
]

COMPILED_OUTPUT_PATTERNS = [re.compile(p, re.IGNORECASE) for p in OUTPUT_DANGER_PATTERNS]


def filter_output(response: str) -> tuple[str, bool, list[str]]:
    threats = [p.pattern for p in COMPILED_OUTPUT_PATTERNS if p.search(response)]
    if threats:
        return (
            "⚠️ Response blocked by output security filter. "
            "A potential injection artifact was detected. "
            "Please rephrase your question.",
            False,
            threats,
        )
    return response, True, []


# ─────────────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────────────

def run_enterprise_pipeline(
    user_query:  str,
    documents:   list[Document],
    user:        UserContext,
) -> dict:
    """
    Run the full 12-layer enterprise secure RAG pipeline.
    Returns complete result with security metadata.
    """
    audit = AuditRecord(
        session_id     = user.session_id,
        user_role      = user.role,
        original_query = user_query,
        docs_retrieved = len(documents),
    )

    pipeline_log = []

    # ── [1] Input Sanitization ────────────────────────────────
    clean_query, input_secrets = redact_secrets(user_query)
    audit.secrets_redacted     = input_secrets

    input_risk = score_text(clean_query, session_id=user.session_id)
    audit.input_threats = [f["factor"] for f in input_risk.triggered_factors]

    if input_risk.decision == "BLOCK":
        audit.response_blocked = True
        audit.risk_score       = input_risk.total_score
        audit.risk_level       = input_risk.level
        audit.risk_decision    = input_risk.decision
        write_audit_log(audit)
        return _blocked_response("Input blocked: high-risk query detected.", audit, input_risk)

    pipeline_log.append(f"[1] Input OK — risk score: {input_risk.total_score}")
    audit.sanitized_query = clean_query

    # ── [2] Risk Score on query ───────────────────────────────
    audit.risk_score  = input_risk.total_score
    audit.risk_level  = input_risk.level
    audit.risk_decision = input_risk.decision
    pipeline_log.append(f"[2] Risk: {input_risk.level} ({input_risk.total_score}/100)")

    # ── [3] Access Control ────────────────────────────────────
    allowed_docs, violations = filter_by_access(documents, user)
    audit.access_violations  = violations
    pipeline_log.append(f"[3] Access: {len(allowed_docs)}/{len(documents)} docs allowed")

    # ── [4] Trust Filter ──────────────────────────────────────
    for doc in allowed_docs:
        assign_trust_score(doc)

    trusted_docs, untrusted = filter_by_trust(allowed_docs)
    audit.docs_after_trust   = len(trusted_docs)
    pipeline_log.append(f"[4] Trust: {len(trusted_docs)} trusted, {len(untrusted)} rejected")

    # ── [5] Context Firewall ──────────────────────────────────
    firewalled_docs, fw_log  = apply_context_firewall(trusted_docs)
    audit.docs_after_firewall = len(firewalled_docs)
    pipeline_log.append(f"[5] Firewall: removed commands from {len(fw_log)} docs")

    # ── [6] Embedding Poison Gate ─────────────────────────────
    clean_docs, poisoned     = validate_before_indexing(firewalled_docs)
    pipeline_log.append(f"[6] Poison gate: {len(poisoned)} poisoned docs removed")

    # ── [7] Risk Score Documents ──────────────────────────────
    scored_docs, flagged     = score_documents(clean_docs, session_id=user.session_id)
    audit.doc_threats        = [{"doc": f["doc_id"], "score": f["report"].total_score} for f in flagged]
    pipeline_log.append(f"[7] Doc risk: {len(flagged)} docs flagged and removed")

    # ── [8] LLM Security Auditor (semantic) ───────────────────
    audited_docs, llm_flagged = audit_documents(scored_docs, risk_threshold=0.6)
    audit.docs_after_audit    = len(audited_docs)
    pipeline_log.append(f"[8] LLM auditor: {len(llm_flagged)} docs flagged by LLM")

    # ── Redact secrets in documents ───────────────────────────
    for doc in audited_docs:
        clean_content, secrets_found = redact_secrets(doc.content)
        doc.content = clean_content
        if secrets_found:
            audit.secrets_redacted.extend(secrets_found)

    # Guard: if no docs left after all filters
    if not audited_docs:
        audit.response_blocked = True
        write_audit_log(audit)
        return _blocked_response(
            "All retrieved documents were flagged as unsafe. Cannot generate a safe response.",
            audit, input_risk
        )

    # ── [8] Build cited prompt ────────────────────────────────
    messages = build_cited_prompt(clean_query, audited_docs)
    pipeline_log.append("[8] Cited prompt built")

    # ── Call LLM ──────────────────────────────────────────────
    response_obj = client.chat.completions.create(
        model       = GENERATION_MODEL,
        messages    = messages,
        temperature = 0.2,
    )
    raw_response = response_obj.choices[0].message.content

    # ── [9] Grounding Validation ──────────────────────────────
    grounding = validate_grounding(raw_response, audited_docs)
    audit.grounded = grounding["grounded"]
    pipeline_log.append(f"[9] Grounding: {grounding['verdict']} (confidence: {grounding['confidence']})")

    # ── [10] Output Filter ────────────────────────────────────
    final_response, is_safe, output_threats = filter_output(raw_response)
    audit.output_threats   = output_threats
    audit.response_blocked = not is_safe
    pipeline_log.append(f"[10] Output filter: {'SAFE' if is_safe else 'BLOCKED'}")

    # ── [11] Citation Verification ────────────────────────────
    citation_report = verify_citations(final_response, audited_docs)
    pipeline_log.append(f"[11] Citations: {citation_report['verdict']} (score: {citation_report['citation_score']})")

    # ── [12] Audit Log ────────────────────────────────────────
    audit.final_response = final_response
    write_audit_log(audit)
    pipeline_log.append("[12] Audit record written")

    return {
        "query":            user_query,
        "response":         final_response,
        "is_safe":          is_safe,
        "grounding":        grounding,
        "citation_report":  citation_report,
        "risk_report": {
            "score":    input_risk.total_score,
            "level":    input_risk.level,
            "decision": input_risk.decision,
        },
        "docs_used":        len(audited_docs),
        "pipeline_log":     pipeline_log,
        "audit_id":         audit.request_id,
    }


# ─────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────

def _blocked_response(reason: str, audit: AuditRecord, risk=None) -> dict:
    return {
        "query":        audit.original_query,
        "response":     f"🚫 Request blocked: {reason}",
        "is_safe":      False,
        "blocked":      True,
        "risk_report":  {
            "score":    risk.total_score  if risk else 0,
            "level":    risk.level        if risk else "UNKNOWN",
            "decision": "BLOCK",
        },
        "audit_id":     audit.request_id,
        "pipeline_log": [f"BLOCKED: {reason}"],
    }