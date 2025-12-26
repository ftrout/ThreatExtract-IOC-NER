#!/usr/bin/env python3
"""
Generate Sample Training Data for ThreatExtract-IOC-NER

This script generates realistic synthetic training data for the IOC
extraction NER model, using threat intelligence templates and patterns.

Usage:
    python scripts/generate_sample_data.py --output data/processed --num_examples 1000
"""

import argparse
import json
import logging
import random
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Realistic IOC samples organized by entity type
IOC_SAMPLES = {
    "MALWARE": [
        "Emotet", "TrickBot", "Ryuk", "WannaCry", "NotPetya", "Dridex",
        "QakBot", "IcedID", "Raccoon Stealer", "RedLine Stealer",
        "Agent Tesla", "FormBook", "LokiBot", "NanoCore", "njRAT",
        "Remcos", "AsyncRAT", "STOP Ransomware", "Conti", "LockBit",
        "BlackCat", "Hive", "REvil", "DarkSide", "Maze", "Netwalker",
        "Sodinokibi", "Dharma", "Phobos", "GandCrab", "Cerber",
        "CryptoLocker", "Petya", "Bad Rabbit", "SamSam",
    ],
    "THREAT_ACTOR": [
        "APT29", "APT28", "APT41", "APT38", "APT33", "APT32", "APT31",
        "Lazarus Group", "Kimsuky", "Turla", "Sandworm", "FIN7", "FIN8",
        "FIN11", "Carbanak", "Cobalt Group", "TA505", "TA551", "TA571",
        "Wizard Spider", "Evil Corp", "DarkSide", "REvil Operators",
        "Nobelium", "Hafnium", "Phosphorus", "Charming Kitten",
        "MuddyWater", "OilRig", "Equation Group", "Fancy Bear",
        "Cozy Bear", "Scattered Spider", "LAPSUS$",
    ],
    "TOOL": [
        "Cobalt Strike", "Mimikatz", "Metasploit", "Empire", "BloodHound",
        "SharpHound", "Impacket", "CrackMapExec", "Rubeus", "Kerberoast",
        "PowerSploit", "Covenant", "Sliver", "Brute Ratel", "PoshC2",
        "Havoc", "Mythic", "PSExec", "WMIExec", "SMBExec", "Evil-WinRM",
        "Chisel", "Ligolo", "ngrok", "Cloudflared", "LaZagne", "Responder",
        "Inveigh", "Certify", "ADCSPwn", "Certipy", "Nmap", "Masscan",
    ],
    "IPV4": [
        "185.220.101.1", "91.219.28.45", "45.33.32.156", "198.51.100.1",
        "203.0.113.50", "192.0.2.1", "172.217.14.206", "8.8.8.8",
        "185.143.223.34", "91.234.99.42", "45.227.253.107", "23.227.38.65",
        "193.37.69.132", "5.188.206.76", "94.102.49.190", "185.25.51.114",
        "217.8.117.147", "185.234.219.192", "172.67.188.1", "104.21.32.88",
    ],
    "IPV6": [
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "fe80::1", "::1", "2607:f8b0:4004:800::200e",
        "2a03:2880:f12f:83:face:b00c:0:25de",
    ],
    "DOMAIN": [
        "evil-domain.com", "malware-c2.net", "phishing-site.org",
        "data-exfil.io", "backdoor-server.xyz", "ransomware-payment.onion",
        "update-server.info", "cdn-download.club", "secure-login.site",
        "account-verify.net", "microsoft-update.download", "google-auth.info",
        "office365-login.com", "banking-secure.net", "crypto-wallet.io",
        "document-share.cloud", "invoice-payment.biz", "tracking-delivery.info",
    ],
    "URL": [
        "https://evil.com/payload.exe", "http://malware.net/dropper.dll",
        "https://phishing.com/login.php", "http://c2-server.net/beacon",
        "https://cdn.malicious.io/stage2.ps1", "http://45.33.32.156/shell.sh",
        "https://update.fake-microsoft.com/patch.msi",
        "http://data-exfil.net/upload.php", "https://ransomware.io/decrypt",
    ],
    "EMAIL": [
        "attacker@malicious.com", "phisher@evil-domain.net",
        "support@fake-microsoft.com", "billing@phishing-site.org",
        "admin@compromised.io", "noreply@malware-c2.net",
        "contact@ransomware-payment.onion", "hr@fake-company.biz",
    ],
    "MD5": [
        "d41d8cd98f00b204e9800998ecf8427e",
        "098f6bcd4621d373cade4e832627b4f6",
        "5d41402abc4b2a76b9719d911017c592",
        "7d793037a0760186574b0282f2f435e7",
        "e99a18c428cb38d5f260853678922e03",
        "21232f297a57a5a743894a0e4a801fc3",
        "a3c65c2974b89e4a0b6e10e0e3d3c9f2",
    ],
    "SHA1": [
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12",
        "40bd001563085fc35165329ea1ff5c5ecbdbbeef",
        "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d",
        "7c4a8d09ca3762af61e59520943dc26494f8941b",
    ],
    "SHA256": [
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "a948904f2f0f479b8f8564cbf12dac6b0f3d6b9b81c3b2a5e7b3f5e3c2d1a0b9",
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    ],
    "CVE": [
        "CVE-2021-44228", "CVE-2023-34362", "CVE-2023-27350", "CVE-2022-41040",
        "CVE-2022-41082", "CVE-2021-34527", "CVE-2020-0796", "CVE-2019-19781",
        "CVE-2021-26855", "CVE-2021-27065", "CVE-2020-1472", "CVE-2021-40444",
        "CVE-2022-30190", "CVE-2023-23397", "CVE-2023-38831", "CVE-2023-4966",
    ],
    "CAMPAIGN": [
        "Operation Aurora", "SolarWinds Attack", "NotPetya Campaign",
        "WannaCry Outbreak", "Operation Sharpshooter", "Operation GhostShell",
        "Campaign Harvest", "Operation Spalax", "Dark Halo", "Sunburst Attack",
        "Operation CloudHopper", "Operation Soft Cell", "Kaseya VSA Attack",
        "MOVEit Campaign", "Log4Shell Exploitation", "ProxyLogon Attack",
    ],
    "TECHNIQUE": [
        "T1059", "T1059.001", "T1566", "T1566.001", "T1078", "T1105",
        "T1027", "T1055", "T1053", "T1547", "T1082", "T1083", "T1003",
        "Spearphishing", "Credential Dumping", "Lateral Movement",
        "Privilege Escalation", "Defense Evasion", "Command and Control",
        "Exfiltration", "Initial Access", "Persistence", "Execution",
    ],
    "REGISTRY_KEY": [
        "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM\\SYSTEM\\CurrentControlSet\\Services",
        "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command",
        "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
    ],
    "FILE_PATH": [
        "C:\\Windows\\System32\\malware.dll",
        "C:\\Users\\Public\\Documents\\payload.exe",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\backdoor.exe",
        "/tmp/shell.sh", "/var/tmp/miner", "/usr/local/bin/malicious",
        "C:\\Windows\\Temp\\update.exe", "C:\\Users\\Admin\\AppData\\Local\\Temp\\dropper.dll",
    ],
    "FILE_NAME": [
        "payload.exe", "dropper.dll", "malware.doc", "exploit.pdf",
        "invoice.xlsm", "document.docm", "update.msi", "setup.exe",
        "shell.ps1", "beacon.dll", "loader.exe", "stage2.bin",
        "ransomware.exe", "crypter.dll", "keylogger.exe", "stealer.exe",
    ],
}

# Realistic threat intelligence text templates
TEMPLATES = [
    # Malware analysis reports
    "Analysis of {MALWARE} revealed connections to {IPV4} and {DOMAIN}.",
    "The {MALWARE} sample with hash {SHA256} was distributed via {URL}.",
    "{MALWARE} uses {TOOL} for credential harvesting and connects to {DOMAIN}.",
    "Researchers identified {MALWARE} exploiting {CVE} in the wild.",
    "The malware {MALWARE} drops {FILE_NAME} in {FILE_PATH} for persistence.",

    # Threat actor reports
    "{THREAT_ACTOR} has been observed using {MALWARE} and {TOOL} in recent campaigns.",
    "Attribution links the attack to {THREAT_ACTOR} based on TTPs and infrastructure.",
    "{THREAT_ACTOR} exploited {CVE} to deploy {MALWARE} against targeted organizations.",
    "The group {THREAT_ACTOR} uses {TECHNIQUE} for initial access via {EMAIL}.",
    "{THREAT_ACTOR} infrastructure includes {IPV4} and {DOMAIN}.",

    # Incident response
    "IOCs from the incident include IP {IPV4}, domain {DOMAIN}, and hash {MD5}.",
    "The attacker used {TOOL} to dump credentials and moved laterally using {TECHNIQUE}.",
    "Registry persistence was established at {REGISTRY_KEY} by {MALWARE}.",
    "Malicious file {FILE_NAME} with SHA256 {SHA256} was observed executing {TECHNIQUE}.",
    "Network traffic to {IPV4} was identified as {MALWARE} C2 communication.",

    # Vulnerability exploitation
    "{CVE} is being actively exploited by {THREAT_ACTOR} to deploy {MALWARE}.",
    "Exploitation of {CVE} leads to deployment of {FILE_NAME} from {URL}.",
    "Attackers leverage {CVE} combined with {TECHNIQUE} for privilege escalation.",
    "The vulnerability {CVE} allows remote code execution via {MALWARE}.",
    "Patch immediately for {CVE} as {THREAT_ACTOR} is targeting exposed systems.",

    # Campaign reports
    "{CAMPAIGN} leveraged {MALWARE} distributed from {DOMAIN}.",
    "The {CAMPAIGN} attack chain uses {CVE}, {TECHNIQUE}, and {TOOL}.",
    "Indicators from {CAMPAIGN} include {IPV4}, {SHA256}, and {DOMAIN}.",
    "{THREAT_ACTOR} orchestrated {CAMPAIGN} using {MALWARE} payloads.",
    "Attribution of {CAMPAIGN} points to {THREAT_ACTOR} based on infrastructure overlap.",

    # Tool usage
    "{TOOL} was used to establish persistence via {REGISTRY_KEY}.",
    "Attackers deployed {TOOL} for lateral movement to {IPV4}.",
    "The use of {TOOL} indicates sophisticated {THREAT_ACTOR} activity.",
    "{TOOL} beacon configuration points to {DOMAIN} on port 443.",
    "Memory forensics revealed {TOOL} injection using {TECHNIQUE}.",

    # Multi-IOC sentences
    "The attack originated from {IPV4}, used {MALWARE}, exploited {CVE}, and exfiltrated data to {DOMAIN}.",
    "{THREAT_ACTOR} sent {EMAIL} containing {FILE_NAME} which downloaded {MALWARE} from {URL}.",
    "File {FILE_NAME} with MD5 {MD5} connects to {IPV4} and {DOMAIN} for C2.",
    "The {CAMPAIGN} campaign by {THREAT_ACTOR} uses {TECHNIQUE} and {TOOL} to deploy {MALWARE}.",
    "Indicators: IP {IPV4}, domain {DOMAIN}, hash {SHA256}, CVE {CVE}.",

    # Technical details
    "The dropper creates {FILE_PATH} and establishes persistence in {REGISTRY_KEY}.",
    "SHA1 hash {SHA1} corresponds to {MALWARE} variant detected on {DOMAIN}.",
    "{TECHNIQUE} technique observed with connections to {IPV4} using {TOOL}.",
    "Malicious document {FILE_NAME} exploits {CVE} to execute PowerShell.",
    "C2 beacon to {URL} using {TOOL} with encrypted traffic.",
]


def generate_example(template: str) -> Dict[str, Any]:
    """
    Generate a single training example from a template.

    Args:
        template: Template string with entity placeholders

    Returns:
        Dictionary with text and entities
    """
    text = template
    entities = []

    # Find all placeholders and replace them
    placeholder_pattern = re.compile(r"\{(\w+)\}")

    # Track offset changes as we replace placeholders
    offset = 0

    for match in placeholder_pattern.finditer(template):
        entity_type = match.group(1)

        if entity_type not in IOC_SAMPLES:
            continue

        # Calculate adjusted positions
        original_start = match.start()
        original_end = match.end()
        placeholder = match.group(0)

        # Get a random value for this entity type
        value = random.choice(IOC_SAMPLES[entity_type])

        # Calculate where this entity will be in the final text
        current_pos = original_start + offset
        end_pos = current_pos + len(value)

        # Replace in text
        text = text[:current_pos] + value + text[current_pos + len(placeholder):]

        # Add entity
        entities.append({
            "start": current_pos,
            "end": end_pos,
            "label": entity_type,
        })

        # Update offset
        offset += len(value) - len(placeholder)

    return {
        "text": text,
        "entities": entities,
    }


def generate_dataset(
    num_examples: int = 1000,
    train_ratio: float = 0.8,
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """
    Generate train/val/test datasets.

    Args:
        num_examples: Total number of examples to generate
        train_ratio: Fraction for training set
        val_ratio: Fraction for validation set
        test_ratio: Fraction for test set

    Returns:
        Tuple of (train_data, val_data, test_data)
    """
    examples = []

    for _ in range(num_examples):
        template = random.choice(TEMPLATES)
        example = generate_example(template)
        examples.append(example)

    # Shuffle and split
    random.shuffle(examples)

    train_size = int(num_examples * train_ratio)
    val_size = int(num_examples * val_ratio)

    train_data = examples[:train_size]
    val_data = examples[train_size:train_size + val_size]
    test_data = examples[train_size + val_size:]

    return train_data, val_data, test_data


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate sample training data for ThreatExtract-IOC-NER"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/processed",
        help="Output directory for generated data",
    )
    parser.add_argument(
        "--num_examples",
        type=int,
        default=1000,
        help="Number of examples to generate",
    )
    parser.add_argument(
        "--train_ratio",
        type=float,
        default=0.8,
        help="Fraction for training set",
    )
    parser.add_argument(
        "--val_ratio",
        type=float,
        default=0.1,
        help="Fraction for validation set",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility",
    )

    args = parser.parse_args()

    # Set random seed
    random.seed(args.seed)

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate datasets
    logger.info(f"Generating {args.num_examples} examples...")
    test_ratio = 1.0 - args.train_ratio - args.val_ratio

    train_data, val_data, test_data = generate_dataset(
        num_examples=args.num_examples,
        train_ratio=args.train_ratio,
        val_ratio=args.val_ratio,
        test_ratio=test_ratio,
    )

    # Save datasets
    for name, data in [("train", train_data), ("val", val_data), ("test", test_data)]:
        output_file = output_dir / f"{name}.json"
        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)
        logger.info(f"Saved {len(data)} examples to {output_file}")

    # Print statistics
    logger.info("\nDataset Statistics:")
    logger.info(f"  Training:   {len(train_data)} examples")
    logger.info(f"  Validation: {len(val_data)} examples")
    logger.info(f"  Test:       {len(test_data)} examples")

    # Count entity types
    entity_counts = {}
    for data in [train_data, val_data, test_data]:
        for example in data:
            for entity in example["entities"]:
                entity_type = entity["label"]
                entity_counts[entity_type] = entity_counts.get(entity_type, 0) + 1

    logger.info("\nEntity Type Distribution:")
    for entity_type, count in sorted(entity_counts.items(), key=lambda x: -x[1]):
        logger.info(f"  {entity_type:15s}: {count:5d}")


if __name__ == "__main__":
    main()
