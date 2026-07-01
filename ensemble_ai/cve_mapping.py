"""CVE/CWE mapping for vulnerability classes found by the swarm.

Maps the free-text `vulnerability_class` field to structured CWE IDs, CVSS scores,
and typical CVE references. Used to enrich audit findings and compliance reports.
"""

# Mapping from vulnerability class strings to CWE IDs + CVSS scores + sample CVEs.
# Sources: MITRE CWE (https://cwe.mitre.org/), NVD (https://nvd.nist.gov/).
VULN_TO_CWE = {
    "PHP Object Injection": {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "typical_cves": ["CVE-2024-30103", "CVE-2023-6963"],
    },
    "SSRF": {
        "cwe_id": "CWE-918",
        "cwe_name": "Server-Side Request Forgery",
        "cvss": 9.1,
        "severity": "CRITICAL",
        "typical_cves": ["CVE-2024-21887", "CVE-2023-46805"],
    },
    "BOLA": {
        "cwe_id": "CWE-639",
        "cwe_name": "Authorization Bypass Through User-Controlled Key",
        "cvss": 8.1,
        "severity": "HIGH",
        "typical_cves": ["CVE-2024-25123", "CVE-2023-48022"],
    },
    "IDOR": {  # alias for BOLA
        "cwe_id": "CWE-639",
        "cwe_name": "Authorization Bypass Through User-Controlled Key",
        "cvss": 8.1,
        "severity": "HIGH",
        "typical_cves": ["CVE-2024-25123", "CVE-2023-48022"],
    },
    "SQL Injection": {
        "cwe_id": "CWE-89",
        "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "typical_cves": ["CVE-2024-20767", "CVE-2023-4863"],
    },
    "XSS": {
        "cwe_id": "CWE-79",
        "cwe_name": "Improper Neutralization of Input During Web Page Generation",
        "cvss": 6.1,
        "severity": "MEDIUM",
        "typical_cves": ["CVE-2024-20770", "CVE-2023-41989"],
    },
    "JWT Bypass": {
        "cwe_id": "CWE-347",
        "cwe_name": "Improper Verification of Cryptographic Signature",
        "cvss": 9.1,
        "severity": "CRITICAL",
        "typical_cves": ["CVE-2024-21887", "CVE-2022-23529"],
    },
    "Deserialization": {
        "cwe_id": "CWE-502",
        "cwe_name": "Deserialization of Untrusted Data",
        "cvss": 9.8,
        "severity": "CRITICAL",
        "typical_cves": ["CVE-2024-30103", "CVE-2023-6963"],
    },
}


def enrich_finding(vuln_class: str) -> dict:
    """Look up CWE/CVE info for a vulnerability class.

    Returns a dict with cwe_id, cwe_name, cvss, severity, typical_cves.
    Falls back to CWE-Unknown if the class isn't in the mapping.
    """
    if not vuln_class:
        return {"cwe_id": "CWE-Unknown", "cwe_name": "Unclassified", "cvss": 0.0, "severity": "UNKNOWN", "typical_cves": []}

    # Try exact match, then case-insensitive contains
    for key, info in VULN_TO_CWE.items():
        if key.lower() == vuln_class.lower():
            return info
    for key, info in VULN_TO_CWE.items():
        if key.lower() in vuln_class.lower() or vuln_class.lower() in key.lower():
            return info

    return {"cwe_id": "CWE-Unknown", "cwe_name": "Unclassified", "cvss": 0.0, "severity": "UNKNOWN", "typical_cves": []}
