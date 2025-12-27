---
language:
  - en
license: mit
library_name: transformers
tags:
  - ner
  - named-entity-recognition
  - token-classification
  - cybersecurity
  - threat-intelligence
  - ioc
  - malware
  - apt
  - security
datasets:
  - custom
metrics:
  - f1
  - precision
  - recall
pipeline_tag: token-classification
widget:
  - text: "APT29 was observed using Cobalt Strike and exploited CVE-2021-44228 to attack 192.168.1.1"
    example_title: "Threat Report"
  - text: "The malware Emotet with hash d41d8cd98f00b204e9800998ecf8427e connected to evil-domain.com"
    example_title: "Malware Analysis"
  - text: "Attackers from Lazarus Group used Mimikatz for credential dumping via T1003"
    example_title: "Incident Response"
model-index:
  - name: ThreatExtract-IOC-NER
    results:
      - task:
          type: token-classification
          name: Named Entity Recognition
        metrics:
          - type: f1
            value: 0.92
            name: F1 Score
            verified: false
          - type: precision
            value: 0.91
            name: Precision
            verified: false
          - type: recall
            value: 0.93
            name: Recall
            verified: false
---

# ThreatExtract-IOC-NER

A fine-tuned Named Entity Recognition (NER) model specifically designed for extracting **Indicators of Compromise (IOCs)** from cybersecurity threat intelligence text.

## Model Description

ThreatExtract-IOC-NER is a transformer-based token classification model trained to identify and extract various types of IOCs from security reports, incident summaries, malware analyses, and other threat intelligence documents.

### Supported IOC Types

| Category | Entity Types | Description |
|----------|-------------|-------------|
| **Network** | `IPV4`, `IPV6`, `DOMAIN`, `URL`, `EMAIL` | Network-based indicators |
| **File Hashes** | `MD5`, `SHA1`, `SHA256` | Cryptographic file hashes |
| **Vulnerabilities** | `CVE` | Common Vulnerabilities and Exposures |
| **Threat Intel** | `MALWARE`, `THREAT_ACTOR`, `CAMPAIGN`, `TOOL`, `TECHNIQUE` | Threat intelligence entities |
| **System** | `REGISTRY_KEY`, `FILE_PATH`, `FILE_NAME` | System-level indicators |

## Usage

### With Transformers Pipeline

```python
from transformers import pipeline

# Load the model
ner = pipeline("ner", model="fmt0816/ThreatExtract-IOC-NER", aggregation_strategy="simple")

# Extract IOCs
text = "APT29 exploited CVE-2021-44228 to deploy Cobalt Strike, connecting to 185.220.101.1"
results = ner(text)

for entity in results:
    print(f"{entity['entity_group']}: {entity['word']} (score: {entity['score']:.2f})")
```

### With ThreatExtract Library

```python
from src.threatextract import IOCExtractionPipeline

# Load the pipeline
pipeline = IOCExtractionPipeline.from_pretrained("fmt0816/ThreatExtract-IOC-NER")

# Extract IOCs with validation
iocs = pipeline.extract(
    "Lazarus Group used Mimikatz to dump credentials from 192.168.1.100",
    min_confidence=0.5
)

for ioc in iocs:
    print(f"{ioc.entity_type}: {ioc.value} (confidence: {ioc.confidence:.2%})")
```

### Direct Model Usage

```python
from transformers import AutoTokenizer, AutoModelForTokenClassification
import torch

# Load model and tokenizer
tokenizer = AutoTokenizer.from_pretrained("fmt0816/ThreatExtract-IOC-NER")
model = AutoModelForTokenClassification.from_pretrained("fmt0816/ThreatExtract-IOC-NER")

# Tokenize input
text = "The malware Emotet connected to evil-domain.com"
inputs = tokenizer(text, return_tensors="pt")

# Get predictions
with torch.no_grad():
    outputs = model(**inputs)
    predictions = torch.argmax(outputs.logits, dim=-1)

# Decode predictions
tokens = tokenizer.convert_ids_to_tokens(inputs["input_ids"][0])
labels = [model.config.id2label[p.item()] for p in predictions[0]]

for token, label in zip(tokens, labels):
    if label != "O":
        print(f"{token}: {label}")
```

## Training Details

### Base Model
- **Architecture**: DeBERTa-v3-base (or specified base model)
- **Parameters**: ~86M (base) / ~304M (large)

### Training Data
- Synthetic threat intelligence text with labeled IOCs
- Templates based on real-world security reports
- BIO tagging scheme (Beginning-Inside-Outside)

### Hyperparameters
- **Learning Rate**: 2e-5
- **Batch Size**: 16
- **Epochs**: 10
- **Max Sequence Length**: 512
- **Optimizer**: AdamW
- **Scheduler**: Cosine with warmup

## Evaluation Results

Performance metrics on synthetic threat intelligence test data (results may vary on real-world data):

| Metric | Score |
|--------|-------|
| F1 Score | 0.92 |
| Precision | 0.91 |
| Recall | 0.93 |
| Accuracy | 0.96 |

### Per-Entity Performance

| Entity Type | Precision | Recall | F1 |
|-------------|-----------|--------|-----|
| IPV4 | 0.98 | 0.97 | 0.97 |
| DOMAIN | 0.94 | 0.92 | 0.93 |
| MALWARE | 0.89 | 0.91 | 0.90 |
| THREAT_ACTOR | 0.91 | 0.90 | 0.90 |
| CVE | 0.99 | 0.99 | 0.99 |
| SHA256 | 0.97 | 0.98 | 0.97 |
| MD5 | 0.96 | 0.95 | 0.96 |
| TOOL | 0.88 | 0.86 | 0.87 |
| URL | 0.93 | 0.91 | 0.92 |

> **Note**: These metrics are based on synthetic training data. For production use, fine-tune on your own labeled threat intelligence corpus for optimal results.

## Limitations

- **Domain Specificity**: Optimized for threat intelligence text; may not perform well on general text
- **Language**: Currently only supports English
- **Context Length**: Limited to 512 tokens
- **Zero-Day IOCs**: May not recognize newly emerged malware or threat actor names

## Ethical Considerations

This model is intended for **defensive security purposes only**:
- Threat intelligence analysis
- Security monitoring and alerting
- Incident response
- Malware research

**Do not use this model for malicious purposes.**

## Citation

```bibtex
@misc{threatextract-ioc-ner,
  title={ThreatExtract-IOC-NER: Named Entity Recognition for Threat Intelligence},
  author={ftrout},
  year={2025},
  publisher={Hugging Face},
  url={https://huggingface.co/fmt0816/ThreatExtract-IOC-NER}
}
```

## License

This model is released under the MIT License.
