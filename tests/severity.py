def cvss_to_severity(score: float) -> str:
    """Map CVSS v3.1 score (0.0–10.0) to severity band."""
    if score == 0.0:
        return "None"
    if 0.1 <= score <= 3.9:
        return "Low"
    if 4.0 <= score <= 6.9:
        return "Medium"
    if 7.0 <= score <= 8.9:
        return "High"
    if 9.0 <= score <= 10.0:
        return "Critical"
    raise ValueError("CVSS score must be between 0.0 and 10.0")
