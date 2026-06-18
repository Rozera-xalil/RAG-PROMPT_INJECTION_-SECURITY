"""
access_control.py
-----------------
Layer: Access Control + Citation Enforcement

1. Document-Level Authorization
   Not every user should see every document.
   Admin docs stay hidden from regular users.

2. Citation Enforcement  (NEW — added by Rozêra)
   Forces the LLM to cite sources.
   Responses with uncited claims are rejected or flagged.
   Why: if a claim has no source, it might be hallucinated or injection-induced.
"""

import re
from dataclasses import dataclass
from document_firewall import Document


# ─────────────────────────────────────────────────
# 1. Document-Level Access Control
# ─────────────────────────────────────────────────

# Define which roles can access which document types
ROLE_PERMISSIONS = {
    "admin":     {"public", "internal", "confidential", "admin", "financial"},
    "developer": {"public", "internal", "technical"},
    "qa":        {"public", "internal", "test_reports"},
    "user":      {"public"},
    "guest":     {"public"},
}


@dataclass
class UserContext:
    user_id:    str
    role:       str
    session_id: str


def filter_by_access(documents: list[Document], user: UserContext) -> tuple[list[Document], list[dict]]:
    """
    Remove documents the user is not authorized to see.
    Returns (allowed_docs, access_violation_log).
    """
    allowed_roles   = ROLE_PERMISSIONS.get(user.role, {"public"})
    allowed_docs    = []
    violations      = []

    for doc in documents:
        doc_type = doc.metadata.get("doc_type", "public")

        if doc_type in allowed_roles:
            allowed_docs.append(doc)
        else:
            violations.append({
                "doc_id":    doc.doc_id,
                "doc_type":  doc_type,
                "user_role": user.role,
                "reason":    f"Role '{user.role}' cannot access '{doc_type}' documents",
            })

    return allowed_docs, violations


# ─────────────────────────────────────────────────
# 2. Citation Enforcement
# ─────────────────────────────────────────────────

CITATION_SYSTEM_PROMPT = """You are a precise, source-grounded assistant.

Rules for citations:
- After EVERY factual claim, add the source in parentheses: (Source: DOC_ID)
- If you cannot find a claim in the provided documents, say: "I don't have information about this in the provided context."
- Never invent information. Only cite sources you were given.
- Format your response as plain text with inline citations.

Example:
  "The refund window is 30 days. (Source: DOC1) Premium plans cost $99/month. (Source: DOC2)"
"""


def build_cited_prompt(query: str, documents: list[Document]) -> list[dict]:
    """
    Build a prompt that forces the LLM to cite sources for every claim.
    """
    context_parts = []
    for doc in documents:
        doc_id = doc.doc_id or f"DOC{documents.index(doc)+1}"
        context_parts.append(f"[{doc_id}]\n{doc.content}")

    context_block = "\n\n".join(context_parts)

    user_message = f"""Here are the source documents:

--- SOURCES START ---
{context_block}
--- SOURCES END ---

Answer this question, citing sources inline for every claim:
{query}
"""

    return [
        {"role": "system", "content": CITATION_SYSTEM_PROMPT},
        {"role": "user",   "content": user_message},
    ]


def verify_citations(response: str, documents: list[Document]) -> dict:
    """
    Check that every citation in the response refers to a real document.
    Also flag sentences that make claims WITHOUT any citation.

    Returns citation verification report.
    """
    # Extract all cited doc IDs from the response
    cited_ids   = set(re.findall(r"\(Source:\s*([\w\d]+)\)", response))
    valid_ids   = {doc.doc_id for doc in documents if doc.doc_id}

    # Check for invalid citations (hallucinated sources)
    invalid_citations = cited_ids - valid_ids

    # Find sentences without any citation
    sentences           = re.split(r'(?<=[.!?])\s+', response)
    uncited_sentences   = []
    for sentence in sentences:
        has_citation      = bool(re.search(r"\(Source:", sentence))
        is_factual        = len(sentence.split()) > 5   # skip short non-claim sentences
        is_disclaimer     = "don't have information" in sentence.lower()
        if is_factual and not has_citation and not is_disclaimer:
            uncited_sentences.append(sentence)

    citation_score = 1.0
    if uncited_sentences:
        citation_score -= 0.2 * min(len(uncited_sentences), 4)
    if invalid_citations:
        citation_score -= 0.3 * len(invalid_citations)

    citation_score = max(0.0, citation_score)

    return {
        "cited_ids":          list(cited_ids),
        "invalid_citations":  list(invalid_citations),
        "uncited_sentences":  uncited_sentences[:5],   # show first 5
        "citation_score":     round(citation_score, 2),
        "verdict":            "PASS" if citation_score >= 0.7 else "WARN",
    }
