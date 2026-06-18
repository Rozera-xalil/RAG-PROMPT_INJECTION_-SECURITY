"""
audit_logger.py
---------------
Layer: Audit & Monitoring

Logs every request with full security context:
  - user / session
  - original query
  - retrieved documents
  - risk score
  - what was blocked and why
  - final response

Stored as JSON lines (one per request) — easy to query later.
In production: replace file logging with ElasticSearch or a SIEM tool.
"""

import json
import time
import uuid
from pathlib import Path
from dataclasses import dataclass, field, asdict


AUDIT_LOG_PATH = Path("audit_log.jsonl")


@dataclass
class AuditRecord:
    request_id:         str   = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:          float = field(default_factory=time.time)
    session_id:         str   = "unknown"
    user_role:          str   = "user"

    # Query
    original_query:     str   = ""
    sanitized_query:    str   = ""

    # Retrieval
    docs_retrieved:     int   = 0
    docs_after_trust:   int   = 0
    docs_after_firewall: int  = 0
    docs_after_audit:   int   = 0

    # Risk
    risk_score:         int   = 0
    risk_level:         str   = "LOW"
    risk_decision:      str   = "ALLOW"

    # Threats
    input_threats:      list  = field(default_factory=list)
    doc_threats:        list  = field(default_factory=list)
    output_threats:     list  = field(default_factory=list)
    secrets_redacted:   list  = field(default_factory=list)

    # Output
    grounded:           bool  = True
    response_blocked:   bool  = False
    final_response:     str   = ""   # truncated for log size

    # Access control
    access_violations:  list  = field(default_factory=list)


def write_audit_log(record: AuditRecord, log_path: Path = AUDIT_LOG_PATH):
    """
    Append one AuditRecord as a JSON line.
    Each line is a complete, self-contained record.
    """
    record_dict = asdict(record)
    # Truncate final response for log
    record_dict["final_response"] = record_dict["final_response"][:300]

    with open(log_path, "a") as f:
        f.write(json.dumps(record_dict) + "\n")


def read_audit_logs(log_path: Path = AUDIT_LOG_PATH) -> list[dict]:
    """Read all audit records from log file."""
    if not log_path.exists():
        return []
    records = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    return records


def get_stats(log_path: Path = AUDIT_LOG_PATH) -> dict:
    """
    Compute summary statistics from audit log.
    Useful for security dashboards.
    """
    records = read_audit_logs(log_path)
    if not records:
        return {"total": 0}

    total          = len(records)
    blocked        = sum(1 for r in records if r.get("response_blocked"))
    high_risk      = sum(1 for r in records if r.get("risk_level") in ("HIGH", "CRITICAL"))
    not_grounded   = sum(1 for r in records if not r.get("grounded"))
    avg_risk       = sum(r.get("risk_score", 0) for r in records) / total

    threat_types   = {}
    for record in records:
        for threat in record.get("input_threats", []) + record.get("doc_threats", []):
            if isinstance(threat, dict):
                name = threat.get("factor", "unknown")
            else:
                name = str(threat)
            threat_types[name] = threat_types.get(name, 0) + 1

    return {
        "total_requests":    total,
        "blocked":           blocked,
        "block_rate":        f"{blocked/total*100:.1f}%",
        "high_risk":         high_risk,
        "not_grounded":      not_grounded,
        "avg_risk_score":    round(avg_risk, 1),
        "top_threat_types":  sorted(threat_types.items(), key=lambda x: -x[1])[:5],
    }
