# ThreatExtract-IOC-NER

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Hugging Face](https://img.shields.io/badge/%F0%9F%A4%97%20Hugging%20Face-Model-orange)](https://huggingface.co/fmt0816/ThreatExtract-IOC-NER)

A production-ready Named Entity Recognition (NER) model for extracting **Indicators of Compromise (IOCs)** from cybersecurity threat intelligence text.

## 🎯 Overview

ThreatExtract-IOC-NER is a fine-tuned transformer model that automatically identifies and extracts security-relevant entities from threat reports, incident summaries, malware analyses, and other cybersecurity documents.

### Supported IOC Types

| Category | Entity Types | Examples |
|----------|-------------|----------|
| **Network** | `IPV4`, `IPV6`, `DOMAIN`, `URL`, `EMAIL` | `192.168.1.1`, `evil-domain.com` |
| **File Hashes** | `MD5`, `SHA1`, `SHA256` | `d41d8cd98f00b204e9800998ecf8427e` |
| **Vulnerabilities** | `CVE` | `CVE-2021-44228` |
| **Threat Intel** | `MALWARE`, `THREAT_ACTOR`, `CAMPAIGN`, `TOOL`, `TECHNIQUE` | `Emotet`, `APT29`, `Cobalt Strike` |
| **System** | `REGISTRY_KEY`, `FILE_PATH`, `FILE_NAME` | `payload.exe`, `HKLM\Software\...` |

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/fmt0816/ThreatExtract-IOC-NER.git
cd ThreatExtract-IOC-NER

# Install dependencies
pip install -r requirements.txt

# Install in development mode (optional)
pip install -e .
```

### Basic Usage

```python
from src.threatextract import IOCExtractionPipeline

# Load the model
pipeline = IOCExtractionPipeline.from_pretrained("fmt0816/ThreatExtract-IOC-NER")

# Extract IOCs
text = """
APT29 was observed using Cobalt Strike to establish persistence.
The attackers exploited CVE-2021-44228 and connected to C2 at 185.220.101.1.
Malware sample Emotet was deployed with hash d41d8cd98f00b204e9800998ecf8427e.
"""

iocs = pipeline.extract(text)
for ioc in iocs:
    print(f"{ioc.entity_type}: {ioc.value} (confidence: {ioc.confidence:.2%})")
```

**Output:**
```
THREAT_ACTOR: APT29 (confidence: 98.50%)
TOOL: Cobalt Strike (confidence: 97.20%)
CVE: CVE-2021-44228 (confidence: 99.10%)
IPV4: 185.220.101.1 (confidence: 96.80%)
MALWARE: Emotet (confidence: 98.90%)
MD5: d41d8cd98f00b204e9800998ecf8427e (confidence: 95.40%)
```

### Using with Transformers

```python
from transformers import pipeline

ner = pipeline("ner", model="fmt0816/ThreatExtract-IOC-NER", aggregation_strategy="simple")
results = ner("The malware TrickBot connected to evil-domain.com")
```

## 🎮 Gradio Demo

Run the interactive web demo:

```bash
# Start the demo
python app.py

# With a specific model
python app.py --model_path ./output/threatextract-ioc-ner/final_model

# Create a public shareable link
python app.py --share
```

Access at `http://localhost:7860`

## 🏋️ Training

### Generate Training Data

```bash
# Generate synthetic training data (recommended: 10,000+ examples)
python scripts/generate_sample_data.py --output data/processed --num_examples 10000
```

### Train the Model

```bash
# Train with default configuration
python scripts/train.py --config configs/training_config.yaml

# Train with custom parameters
python scripts/train.py \
    --base_model microsoft/deberta-v3-base \
    --epochs 10 \
    --batch_size 16 \
    --learning_rate 2e-5 \
    --output_dir ./output/my-model

# Push to Hugging Face Hub
python scripts/train.py \
    --config configs/training_config.yaml \
    --push_to_hub \
    --hub_model_id username/ThreatExtract-IOC-NER
```

### Training Configuration

Edit `configs/training_config.yaml`:

```yaml
model:
  base_model: "microsoft/deberta-v3-base"
  max_length: 512

training:
  num_train_epochs: 10
  per_device_train_batch_size: 16
  learning_rate: 2.0e-5
  warmup_ratio: 0.1

evaluation:
  strategy: "epoch"
  metric_for_best_model: "eval_f1"
```

### Supported Base Models

- `microsoft/deberta-v3-base` (recommended)
- `microsoft/deberta-v3-large`
- `bert-base-cased`
- `roberta-base`
- `distilbert-base-cased`
- `jackaduma/SecBERT` (security domain)

## 📊 Evaluation

```bash
# Evaluate a trained model
python scripts/evaluate.py \
    --model_path ./output/threatextract-ioc-ner/final_model \
    --test_file data/processed/test.json \
    --output_file results.json
```

## 📁 Project Structure

```
ThreatExtract-IOC-NER/
├── .github/
│   ├── ISSUE_TEMPLATE/        # Issue templates
│   └── pull_request_template.md
├── src/
│   ├── __init__.py
│   └── threatextract/
│       ├── __init__.py
│       ├── labels.py          # IOC label definitions
│       ├── model.py           # Core NER model class
│       ├── pipeline.py        # High-level extraction pipeline
│       └── data.py            # Data processing utilities
├── scripts/
│   ├── train.py               # Training script
│   ├── evaluate.py            # Evaluation script
│   ├── generate_sample_data.py # Synthetic data generation
│   └── push_to_hub.py         # Hugging Face Hub upload
├── configs/
│   └── training_config.yaml   # Training configuration
├── data/
│   ├── raw/                   # Raw data files
│   └── processed/             # Processed training data
├── tests/
│   ├── test_labels.py
│   └── test_data.py
├── app.py                     # Gradio demo
├── MODEL_CARD.md              # Hugging Face model card
├── DATASET_CARD.md            # Dataset documentation
├── SECURITY.md                # Security policy
├── Dockerfile                 # GPU training container
├── requirements.txt
├── pyproject.toml
└── README.md
```

## 🔧 Advanced Usage

### Custom IOC Validation

```python
from src.threatextract import IOCExtractionPipeline

pipeline = IOCExtractionPipeline.from_pretrained(
    "fmt0816/ThreatExtract-IOC-NER",
    validate_iocs=True,      # Enable regex validation
    min_confidence=0.7,       # Higher confidence threshold
    deduplicate=True,         # Remove duplicates
)
```

### Filter by Entity Type

```python
# Extract only network IOCs
network_iocs = pipeline.extract(
    text,
    entity_types=["IPV4", "DOMAIN", "URL"]
)
```

### STIX 2.1 Output

```python
# Export as STIX bundle
stix_bundle = pipeline.extract_to_stix(text)
```

### HTML Highlighting

```python
# Get highlighted HTML
highlighted = pipeline.highlight_text(text)
```

## 📋 Data Format

### JSON Format (Recommended)

```json
[
  {
    "text": "The malware Emotet connected to 192.168.1.1",
    "entities": [
      {"start": 12, "end": 18, "label": "MALWARE"},
      {"start": 32, "end": 43, "label": "IPV4"}
    ]
  }
]
```

### CoNLL Format

```
The O
malware O
Emotet B-MALWARE
connected O
to O
192.168.1.1 B-IPV4

```

## 🧪 Testing

```bash
# Run tests
pytest tests/ -v

# With coverage
pytest tests/ --cov=src --cov-report=term-missing
```

## 📦 Hugging Face Hub

### Upload Model

```python
from src.threatextract import ThreatExtractNER

model = ThreatExtractNER.from_pretrained("./output/threatextract-ioc-ner/final_model")
model.save_pretrained(
    "fmt0816/ThreatExtract-IOC-NER",
    push_to_hub=True,
)
```

### Download Model

```python
from src.threatextract import ThreatExtractNER

model = ThreatExtractNER.from_pretrained("fmt0816/ThreatExtract-IOC-NER")
```

## 🔒 Security

For security concerns, please see our [Security Policy](SECURITY.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Hugging Face Transformers](https://huggingface.co/transformers)
- [seqeval](https://github.com/chakki-works/seqeval) for NER evaluation
- The cybersecurity community for threat intelligence research

## 📚 Citation

```bibtex
@misc{threatextract-ioc-ner,
  title={ThreatExtract-IOC-NER: Named Entity Recognition for Threat Intelligence},
  author={ThreatExtract Team},
  year={2025},
  publisher={GitHub},
  url={https://github.com/fmt0816/ThreatExtract-IOC-NER}
}
```

## ⚠️ Disclaimer

This tool is intended for **defensive security purposes only**. Use responsibly for threat intelligence analysis, security monitoring, and incident response. Do not use for malicious purposes.
