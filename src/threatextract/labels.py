"""
IOC Label Definitions for ThreatExtract-IOC-NER

This module defines the label schema for Named Entity Recognition of
Indicators of Compromise (IOCs) in threat intelligence text.

Label Schema follows BIO (Beginning-Inside-Outside) tagging format:
- B-{ENTITY}: Beginning of an entity
- I-{ENTITY}: Inside/continuation of an entity
- O: Outside any entity (not an IOC)

Supported IOC Types:
- IPV4: IPv4 addresses (e.g., 192.168.1.1)
- IPV6: IPv6 addresses (e.g., 2001:0db8:85a3::8a2e:0370:7334)
- DOMAIN: Domain names (e.g., malicious-site.com)
- URL: Full URLs (e.g., https://evil.com/malware.exe)
- EMAIL: Email addresses (e.g., attacker@malicious.com)
- MD5: MD5 file hashes (32 hex characters)
- SHA1: SHA-1 file hashes (40 hex characters)
- SHA256: SHA-256 file hashes (64 hex characters)
- CVE: Common Vulnerabilities and Exposures IDs (e.g., CVE-2023-1234)
- MALWARE: Malware family names (e.g., Emotet, TrickBot)
- THREAT_ACTOR: Threat actor/APT group names (e.g., APT29, Lazarus Group)
- CAMPAIGN: Attack campaign names (e.g., SolarWinds, Operation Aurora)
- TOOL: Hacking tools (e.g., Cobalt Strike, Mimikatz)
- TECHNIQUE: MITRE ATT&CK techniques (e.g., T1059, Spearphishing)
- REGISTRY_KEY: Windows registry keys
- FILE_PATH: File system paths
- FILE_NAME: File names with extensions
"""

from typing import Dict, List

# IOC entity types (without BIO prefix)
IOC_ENTITY_TYPES: List[str] = [
    "IPV4",
    "IPV6",
    "DOMAIN",
    "URL",
    "EMAIL",
    "MD5",
    "SHA1",
    "SHA256",
    "CVE",
    "MALWARE",
    "THREAT_ACTOR",
    "CAMPAIGN",
    "TOOL",
    "TECHNIQUE",
    "REGISTRY_KEY",
    "FILE_PATH",
    "FILE_NAME",
]

# Build BIO labels list
IOC_LABELS: List[str] = ["O"]  # Start with Outside label
for entity_type in IOC_ENTITY_TYPES:
    IOC_LABELS.append(f"B-{entity_type}")
    IOC_LABELS.append(f"I-{entity_type}")

# Label to ID mapping
LABEL2ID: Dict[str, int] = {label: idx for idx, label in enumerate(IOC_LABELS)}

# ID to Label mapping
ID2LABEL: Dict[int, str] = {idx: label for idx, label in enumerate(IOC_LABELS)}

# Number of labels
NUM_LABELS: int = len(IOC_LABELS)

# Entity type descriptions for documentation
ENTITY_DESCRIPTIONS: Dict[str, str] = {
    "IPV4": "IPv4 network addresses (e.g., 192.168.1.1, 10.0.0.1)",
    "IPV6": "IPv6 network addresses (e.g., 2001:0db8:85a3::8a2e:0370:7334)",
    "DOMAIN": "Domain names and hostnames (e.g., malicious-domain.com)",
    "URL": "Full URLs including protocol (e.g., https://evil.com/payload.exe)",
    "EMAIL": "Email addresses used in attacks (e.g., phisher@malicious.com)",
    "MD5": "MD5 file hashes - 32 hexadecimal characters",
    "SHA1": "SHA-1 file hashes - 40 hexadecimal characters",
    "SHA256": "SHA-256 file hashes - 64 hexadecimal characters",
    "CVE": "Common Vulnerabilities and Exposures identifiers (e.g., CVE-2023-1234)",
    "MALWARE": "Malware family or variant names (e.g., Emotet, WannaCry, TrickBot)",
    "THREAT_ACTOR": "Threat actor or APT group names (e.g., APT29, Lazarus Group, FIN7)",
    "CAMPAIGN": "Named attack campaigns (e.g., SolarWinds, Operation Aurora)",
    "TOOL": "Attacker tools and frameworks (e.g., Cobalt Strike, Mimikatz, Empire)",
    "TECHNIQUE": "MITRE ATT&CK techniques or tactics (e.g., T1059, Spearphishing)",
    "REGISTRY_KEY": "Windows registry keys targeted or modified by malware",
    "FILE_PATH": "File system paths (e.g., C:\\Windows\\System32\\malware.dll)",
    "FILE_NAME": "Malicious file names (e.g., payload.exe, dropper.dll)",
}

# Color scheme for visualization (hex colors)
ENTITY_COLORS: Dict[str, str] = {
    "IPV4": "#FF6B6B",
    "IPV6": "#FF8E8E",
    "DOMAIN": "#4ECDC4",
    "URL": "#45B7B8",
    "EMAIL": "#96CEB4",
    "MD5": "#DDA0DD",
    "SHA1": "#E6B0E6",
    "SHA256": "#F0C0F0",
    "CVE": "#FFE66D",
    "MALWARE": "#FF4757",
    "THREAT_ACTOR": "#5352ED",
    "CAMPAIGN": "#3742FA",
    "TOOL": "#FFA502",
    "TECHNIQUE": "#FF7F50",
    "REGISTRY_KEY": "#A8E6CF",
    "FILE_PATH": "#88D8B0",
    "FILE_NAME": "#B8E6CF",
}


def get_entity_type(label: str) -> str:
    """Extract entity type from BIO label.

    Args:
        label: BIO-formatted label (e.g., 'B-MALWARE', 'I-IPV4')

    Returns:
        Entity type without BIO prefix, or 'O' for outside labels
    """
    if label == "O":
        return "O"
    return label.split("-", 1)[1] if "-" in label else label


def is_beginning_label(label: str) -> bool:
    """Check if label is a beginning (B-) label."""
    return label.startswith("B-")


def is_inside_label(label: str) -> bool:
    """Check if label is an inside (I-) label."""
    return label.startswith("I-")


def get_label_for_entity(entity_type: str, position: str = "B") -> str:
    """Get the full BIO label for an entity type.

    Args:
        entity_type: Entity type (e.g., 'MALWARE', 'IPV4')
        position: 'B' for beginning, 'I' for inside

    Returns:
        Full BIO label (e.g., 'B-MALWARE')
    """
    if entity_type not in IOC_ENTITY_TYPES:
        raise ValueError(f"Unknown entity type: {entity_type}")
    if position not in ("B", "I"):
        raise ValueError(f"Position must be 'B' or 'I', got: {position}")
    return f"{position}-{entity_type}"
