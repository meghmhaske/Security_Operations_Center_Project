from .db import recent_events

def detect_for_source(source_ip: str):
    events = recent_events(source_ip, 100)

    failed = [e for e in events if e["event_type"] == "failed_login"]
    successful = [e for e in events if e["event_type"] == "successful_login"]
    escalation = [e for e in events if e["event_type"] == "privilege_escalation"]
    transfers = [e for e in events if e["event_type"] == "data_transfer"]

    detections = []
    score = 0

    # Transparent V1 rules. ML will augment/replace these in a later version.
    if len(failed) >= 5:
        detections.append("brute_force_behavior")
        score += min(50, 20 + len(failed))

    if failed and successful:
        detections.append("successful_login_after_failures")
        score += 15

    if escalation:
        detections.append("privilege_escalation")
        score += 20

    if transfers and any(e["bytes_transferred"] >= 1_000_000 for e in transfers):
        detections.append("unusual_large_data_transfer")
        score += 15

    # Multi-stage correlation
    if failed and successful and escalation and transfers:
        detections.append("possible_account_compromise_chain")
        score += 20

    score = min(100, score)

    if score <= 30:
        severity = "LOW"
    elif score <= 60:
        severity = "MEDIUM"
    elif score <= 80:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    if score >= 85:
        action = "BLOCK_SOURCE_IP_IN_LAB"
    elif score >= 60:
        action = "REVIEW_AND_CONSIDER_BLOCKING"
    elif score >= 31:
        action = "INVESTIGATE"
    else:
        action = "MONITOR"

    return {
        "risk_score": score,
        "severity": severity,
        "detections": detections,
        "recommended_action": action,
    }
