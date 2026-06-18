"""
risk_engine.py
--------------
Layer: Risk Scoring Engine

Instead of binary safe/unsafe — assigns a numeric risk score 0-100.
Each threat factor contributes weighted points.
Composite score determines whether to block, warn, or allow.

Risk Factors:
  Prompt Injection     → +30
  Data Extraction      → +25
  Role Manipulation    → +20
  Secret Access        → +15
  Embedding Poisoning  → +20
  Low Trust Source     → +10
  High Semantic Risk   → +15  ← NEW: added by Rozêra
  Repeated Attempts    → +20  ← NEW: session-level tracking
"""

import re
import time
from dataclasses import dataclass, field
from collections import defaultdict


# ─────────────────────────────────────────────────
# Risk Factor Definitions
# ─────────────────────────────────────────────────

@dataclass
class RiskFactor:
    name:        str
    weight:      int
    patterns:    list
    description: str


RISK_FACTORS = [
    RiskFactor(
        name="prompt_injection",
        weight=30,
        patterns=[
            r"ignore (all )?(previous|prior) instructions?",
            r"forget (your |all )?(previous |prior )?instructions?",
            r"\[SYSTEM\]",
            r"OVERRIDE",
            r"new (system )?prompt",
        ],
        description="Direct attempt to hijack LLM instructions"
    ),
    RiskFactor(
        name="data_extraction",
        weight=25,
        patterns=[
            r"reveal (all|your|the) (system|prompt|data|config|password|key)",
            r"show me (all |your )?(user|internal|private|secret)",
            r"leak (all|your|the)",
            r"send (data|info|details) to",
            r"exfiltrat",
        ],
        description="Attempt to extract sensitive information"
    ),
    RiskFactor(
        name="role_manipulation",
        weight=20,
        patterns=[
            r"you are now",
            r"act as (if )?you (have |are )?no (restriction|limitation)",
            r"pretend (you are|to be)",
            r"\bDAN\b",
            r"developer mode",
            r"unrestricted mode",
            r"jailbreak",
        ],
        description="Attempt to change LLM identity or behavior"
    ),
    RiskFactor(
        name="secret_access",
        weight=15,
        patterns=[
            r"(API|api)[-_]?KEY",
            r"PASSWORD",
            r"TOKEN",
            r"SECRET",
            r"sk-[a-zA-Z0-9]{10,}",   # OpenAI key format
            r"Bearer\s+[a-zA-Z0-9\-_]{10,}",
        ],
        description="Presence of secrets or attempts to access them"
    ),
    RiskFactor(
        name="embedding_poisoning",
        weight=20,
        patterns=[
            r"if (anyone|someone|a user) asks?",
            r"always (say|respond|claim)",
            r"whenever (someone|the user) (asks?|queries?)",
            r"respond with .{0,50} regardless",
        ],
        description="Attempt to manipulate retrieval behavior"
    ),
    # ── NEW: High Semantic Risk ──────────────────────────────────
    RiskFactor(
        name="high_semantic_risk",
        weight=15,
        patterns=[
            r"(above|previous|prior) (context|instruction|system|prompt) (is|are|was|were)? ?(wrong|incorrect|invalid|fake|false)",
            r"this (is a )?(test|simulation|game|roleplay|scenario)",
            r"for (educational|research|testing) purposes? (only)?[,.]? (ignore|bypass|skip)",
            r"hypothetically (speaking)?[,.]? (if )?you (could|were able to|had no)",
        ],
        description="Semantically deceptive framing — tries to trick the model indirectly"
    ),
]


# ─────────────────────────────────────────────────
# Session-Level Attempt Tracker  ← NEW addition
# ─────────────────────────────────────────────────

class SessionTracker:
    """
    Tracks suspicious queries per user session.
    Repeated suspicious attempts escalate the risk score.

    Why? An attacker might use multiple low-risk queries
    to gradually probe the system.
    """
    def __init__(self):
        self._sessions: dict[str, list[dict]] = defaultdict(list)

    def record(self, session_id: str, risk_score: float, query: str):
        self._sessions[session_id].append({
            "timestamp":  time.time(),
            "risk_score": risk_score,
            "query":      query[:100],
        })

    def get_escalation_bonus(self, session_id: str) -> int:
        """
        If user has had 2+ suspicious queries (score > 40) in this session,
        add +20 to current score.
        """
        recent = self._sessions.get(session_id, [])
        suspicious_count = sum(1 for r in recent if r["risk_score"] > 40)

        if suspicious_count >= 2:
            return 20   # repeated attempts → escalate
        return 0

    def get_history(self, session_id: str) -> list[dict]:
        return self._sessions.get(session_id, [])


# Global tracker (in production, use Redis or a DB)
_session_tracker = SessionTracker()


# ─────────────────────────────────────────────────
# Risk Scoring Engine
# ─────────────────────────────────────────────────

@dataclass
class RiskReport:
    total_score:      int
    level:            str        # LOW / MEDIUM / HIGH / CRITICAL
    triggered_factors: list[dict]
    decision:         str        # ALLOW / WARN / BLOCK
    session_bonus:    int = 0
    explanation:      str = ""


RISK_LEVELS = [
    (80, "CRITICAL", "BLOCK"),
    (60, "HIGH",     "BLOCK"),
    (40, "MEDIUM",   "WARN"),
    (0,  "LOW",      "ALLOW"),
]


def score_text(text: str, session_id: str = "default") -> RiskReport:
    """
    Analyze text and return a full RiskReport.
    Checks all risk factors, applies session escalation.
    """
    total_score      = 0
    triggered        = []

    compiled_factors = [
        (factor, [re.compile(p, re.IGNORECASE) for p in factor.patterns])
        for factor in RISK_FACTORS
    ]

    for factor, patterns in compiled_factors:
        matched_patterns = []
        for pattern in patterns:
            if pattern.search(text):
                matched_patterns.append(pattern.pattern)

        if matched_patterns:
            total_score += factor.weight
            triggered.append({
                "factor":      factor.name,
                "weight":      factor.weight,
                "description": factor.description,
                "matched":     matched_patterns,
            })

    # Session escalation bonus
    session_bonus = _session_tracker.get_escalation_bonus(session_id)
    total_score  += session_bonus
    total_score   = min(total_score, 100)   # cap at 100

    # Determine level and decision
    level    = "LOW"
    decision = "ALLOW"
    for threshold, lvl, dec in RISK_LEVELS:
        if total_score >= threshold:
            level    = lvl
            decision = dec
            break

    # Build explanation
    if triggered:
        factor_names = ", ".join(t["factor"] for t in triggered)
        explanation  = f"Triggered: {factor_names}. Score: {total_score}/100."
        if session_bonus > 0:
            explanation += f" Session escalation applied (+{session_bonus})."
    else:
        explanation = "No threats detected."

    # Record in session
    _session_tracker.record(session_id, total_score, text[:100])

    return RiskReport(
        total_score       = total_score,
        level             = level,
        triggered_factors = triggered,
        decision          = decision,
        session_bonus     = session_bonus,
        explanation       = explanation,
    )


def score_documents(documents: list, session_id: str = "default") -> tuple[list, list[dict]]:
    """
    Score all documents. Return (safe_docs, risk_reports_for_flagged).
    Documents with decision=BLOCK are excluded from context.
    """
    safe_docs    = []
    flagged_docs = []

    for doc in documents:
        report = score_text(doc.content, session_id)
        doc.metadata["risk_report"] = {
            "score":    report.total_score,
            "level":    report.level,
            "decision": report.decision,
        }

        if report.decision == "BLOCK":
            flagged_docs.append({
                "doc_id":  doc.doc_id,
                "report":  report,
            })
        else:
            safe_docs.append(doc)

    return safe_docs, flagged_docs
