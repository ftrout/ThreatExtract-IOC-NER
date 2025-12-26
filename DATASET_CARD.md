# Dataset Card for ThreatExtract-IOC-NER Training Data

## Dataset Description

### Dataset Summary

This dataset contains labeled threat intelligence text for training Named Entity Recognition (NER) models to extract Indicators of Compromise (IOCs). The dataset includes synthetic examples generated from threat intelligence templates and patterns commonly found in security reports, incident summaries, and malware analyses.

### Supported Tasks

- **Token Classification / Named Entity Recognition**: Extract IOC entities from cybersecurity text

### Languages

- English (en)

## Dataset Structure

### Data Format

The dataset uses JSON format with the following structure:

```json
[
  {
    "text": "APT29 exploited CVE-2021-44228 to deploy Cobalt Strike at 192.168.1.1",
    "entities": [
      {"start": 0, "end": 5, "label": "THREAT_ACTOR"},
      {"start": 15, "end": 29, "label": "CVE"},
      {"start": 41, "end": 54, "label": "TOOL"},
      {"start": 58, "end": 70, "label": "IPV4"}
    ]
  }
]
```

### Entity Types

| Entity Type | Description | Examples |
|-------------|-------------|----------|
| IPV4 | IPv4 addresses | 192.168.1.1, 10.0.0.1 |
| IPV6 | IPv6 addresses | 2001:0db8:85a3::8a2e:0370:7334 |
| DOMAIN | Domain names | evil-domain.com, malware-c2.net |
| URL | Full URLs | https://evil.com/payload.exe |
| EMAIL | Email addresses | attacker@malicious.com |
| MD5 | MD5 file hashes | d41d8cd98f00b204e9800998ecf8427e |
| SHA1 | SHA-1 file hashes | da39a3ee5e6b4b0d3255bfef95601890afd80709 |
| SHA256 | SHA-256 file hashes | e3b0c44298fc1c149afbf4c8996fb924... |
| CVE | CVE identifiers | CVE-2021-44228, CVE-2023-34362 |
| MALWARE | Malware names | Emotet, TrickBot, Ryuk |
| THREAT_ACTOR | APT/threat groups | APT29, Lazarus Group, FIN7 |
| CAMPAIGN | Attack campaigns | SolarWinds, Operation Aurora |
| TOOL | Attack tools | Cobalt Strike, Mimikatz |
| TECHNIQUE | MITRE ATT&CK techniques | T1059, Spearphishing |
| REGISTRY_KEY | Windows registry keys | HKLM\Software\Microsoft\... |
| FILE_PATH | File system paths | C:\Windows\System32\... |
| FILE_NAME | File names | payload.exe, dropper.dll |

### Data Splits

| Split | Examples | Description |
|-------|----------|-------------|
| train | 800 | Training set |
| validation | 100 | Validation set for hyperparameter tuning |
| test | 100 | Held-out test set for final evaluation |

## Dataset Creation

### Generation Process

The synthetic training data is generated using:

1. **Templates**: Realistic threat intelligence text templates based on common patterns in security reports
2. **Entity Sampling**: Random sampling from curated lists of real-world IOC examples
3. **Position Tracking**: Accurate character-level position tracking for entity spans

### Source Data

Entity examples are curated from:
- Public threat intelligence reports
- MITRE ATT&CK framework
- CVE database patterns
- Common malware naming conventions

### Annotations

Annotations follow the BIO (Beginning-Inside-Outside) tagging scheme:
- `B-{ENTITY}`: Beginning of an entity
- `I-{ENTITY}`: Inside/continuation of an entity
- `O`: Outside any entity

## Considerations for Using the Data

### Social Impact

This dataset is intended for **defensive security purposes**:
- Automated IOC extraction from threat reports
- Security monitoring and alerting
- Incident response acceleration
- Threat intelligence automation

### Limitations

- **Synthetic Data**: Generated from templates; may not capture all real-world variations
- **English Only**: Currently supports English text only
- **Domain Specific**: Optimized for threat intelligence text patterns
- **Entity Coverage**: May not include all possible IOC formats or variations

### Recommendations

For production use:
1. Supplement with real-world labeled threat intelligence data
2. Fine-tune on domain-specific text from your organization
3. Validate extracted IOCs against known patterns
4. Regularly update entity lists with emerging threats

## Additional Information

### Dataset Curator

ThreatExtract Team

### Licensing Information

This dataset is released under the MIT License.

### Citation Information

```bibtex
@dataset{threatextract-ioc-dataset,
  title={ThreatExtract IOC NER Training Dataset},
  author={ThreatExtract Team},
  year={2025},
  publisher={GitHub},
  url={https://github.com/fmt0816/ThreatExtract-IOC-NER}
}
```

### Contributions

We welcome contributions of additional training examples, especially:
- Real-world labeled threat intelligence text (with appropriate permissions)
- New entity types and validation patterns
- Multi-language support
