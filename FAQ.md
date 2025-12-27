# Frequently Asked Questions (FAQ)

## General Questions

### What is ThreatExtract-IOC-NER?

ThreatExtract-IOC-NER is a Named Entity Recognition (NER) model specifically designed to extract Indicators of Compromise (IOCs) from cybersecurity threat intelligence text. It uses transformer-based deep learning to identify and classify various types of security-relevant entities from threat reports, incident summaries, and malware analyses.

### What types of IOCs can the model extract?

The model can extract 17 different types of IOCs:

| Category | Entity Types |
|----------|-------------|
| **Network** | IPv4 addresses, IPv6 addresses, Domains, URLs, Email addresses |
| **File Hashes** | MD5, SHA1, SHA256 |
| **Vulnerabilities** | CVE identifiers |
| **Threat Intelligence** | Malware names, Threat actor/APT groups, Campaigns, Tools, Techniques |
| **System** | Registry keys, File paths, File names |

### Is this model free to use?

Yes, the model is released under the MIT License, which allows for both personal and commercial use with minimal restrictions.

---

## Installation & Setup

### What are the system requirements?

- **Python**: 3.9 or higher
- **Memory**: At least 4GB RAM (8GB+ recommended for training)
- **GPU**: Optional but recommended for faster inference and required for training

### How do I install the model?

```bash
# Clone the repository
git clone https://github.com/ftrout/ThreatExtract-IOC-NER.git
cd ThreatExtract-IOC-NER

# Install dependencies
pip install -r requirements.txt

# Install in development mode (optional)
pip install -e .
```

### Can I use the model without a GPU?

Yes, the model works on CPU. However, inference will be slower compared to GPU. For production deployments with high throughput requirements, a GPU is recommended.

### How do I use the model from Hugging Face Hub?

```python
from transformers import pipeline

ner = pipeline("ner", model="fmt0816/ThreatExtract-IOC-NER", aggregation_strategy="simple")
results = ner("APT29 exploited CVE-2021-44228 to attack 192.168.1.1")
```

---

## Model Usage

### What is the recommended confidence threshold?

The default confidence threshold is 0.5 (50%). For production environments where precision is critical, consider using 0.7-0.8. For research or exploratory analysis where recall is more important, 0.3-0.5 may be appropriate.

### Can the model process multiple texts at once?

Yes, the pipeline supports batch processing:

```python
texts = [
    "APT29 deployed Cobalt Strike...",
    "Emotet connected to 192.168.1.1...",
]
results = pipeline.extract(texts)
```

### What is the maximum text length the model can process?

The model has a maximum sequence length of 512 tokens. Longer texts will be truncated. For very long documents, consider splitting them into smaller chunks and processing each separately.

### How do I validate extracted IOCs?

The pipeline includes built-in regex-based validation for structured IOCs (IP addresses, hashes, CVEs, etc.):

```python
pipeline = IOCExtractionPipeline.from_pretrained(
    "fmt0816/ThreatExtract-IOC-NER",
    validate_iocs=True,  # Enable validation
)
```

Validated IOCs will have `validated=True` in their output.

---

## Training & Fine-tuning

### What base model is recommended for fine-tuning?

We recommend `microsoft/deberta-v3-base` as it provides the best balance between accuracy and resource requirements. For higher accuracy at the cost of more resources, use `microsoft/deberta-v3-large`.

### How much training data do I need?

For reasonable performance:
- Minimum: 1,000 labeled examples
- Recommended: 5,000-10,000 labeled examples
- Production-grade: 50,000+ labeled examples

The quality and diversity of the data is as important as quantity.

### What data format is required for training?

The model supports two formats:

**JSON Format (Recommended):**
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

**CoNLL Format:**
```
The O
malware O
Emotet B-MALWARE
connected O
to O
192.168.1.1 B-IPV4
```

### How long does training take?

Training time depends on:
- Dataset size
- Hardware (GPU type and count)
- Number of epochs

Approximate times for 10,000 examples on a single GPU:
- NVIDIA RTX 3090: ~30-45 minutes
- NVIDIA A100: ~15-20 minutes
- CPU only: Several hours (not recommended)

### Can I generate synthetic training data?

Yes, the repository includes a script for generating synthetic training data:

```bash
python scripts/generate_sample_data.py --output data/processed --num_examples 10000
```

Note: Synthetic data is useful for demonstration and initial training, but for production use, supplement with real-world labeled threat intelligence.

---

## Performance & Accuracy

### What is the model's accuracy?

On synthetic test data, the model achieves approximately:
- **F1 Score**: 0.92
- **Precision**: 0.91
- **Recall**: 0.93

Note: These metrics are on synthetic data. Performance on real-world data may vary and should be evaluated on your specific use case.

### Which IOC types have the best accuracy?

Structured IOCs with consistent patterns perform best:
- **CVE** (F1: 0.99) - Very consistent pattern
- **IPv4** (F1: 0.97) - Well-defined structure
- **SHA256** (F1: 0.97) - Fixed length, hex characters

Less structured entities have more variation:
- **Tool** (F1: 0.87) - Wide variety of naming conventions
- **Threat Actor** (F1: 0.90) - Varied naming patterns

### Why isn't the model recognizing my IOCs?

Common reasons:
1. **Low confidence**: Try lowering `min_confidence` threshold
2. **Text format**: The model works best with properly formatted threat intelligence text
3. **Unknown entities**: New malware or threat actors may not be in training data
4. **Text length**: Very long texts get truncated at 512 tokens

---

## Hugging Face Integration

### How do I upload my trained model to Hugging Face Hub?

```python
from src.threatextract import ThreatExtractNER

model = ThreatExtractNER.from_pretrained("./output/threatextract-ioc-ner/final_model")
model.save_pretrained(
    "your-username/ThreatExtract-IOC-NER",
    push_to_hub=True,
)
```

Make sure you're logged in with `huggingface-cli login` first.

### What files are included in the Hugging Face model?

- `config.json` - Model configuration
- `model.safetensors` - Model weights
- `tokenizer.json` - Tokenizer configuration
- `tokenizer_config.json` - Tokenizer settings
- `special_tokens_map.json` - Special token mappings
- `vocab.txt` (or similar) - Vocabulary file

---

## Troubleshooting

### I'm getting CUDA out of memory errors

Solutions:
1. Reduce batch size: `--batch_size 8` or even `4`
2. Enable gradient checkpointing in config
3. Use a smaller base model (e.g., `distilbert-base-cased`)
4. Use FP16 training (enabled by default)

### The model is running slowly on CPU

This is expected. For faster inference:
1. Use a GPU if available
2. Use batch processing for multiple texts
3. Consider using a smaller model like DistilBERT

### I'm getting tokenizer warnings

Some warnings about tokenizer parallelism are normal and can be ignored. To suppress them:
```python
import os
os.environ["TOKENIZERS_PARALLELISM"] = "false"
```

### The extracted IOC positions are incorrect

This can happen due to:
1. Special characters or unicode in the text
2. Text preprocessing that modifies the original string
3. Subword tokenization boundaries

Use the raw text without preprocessing for best position accuracy.

---

## Best Practices

### How should I preprocess input text?

Minimal preprocessing is recommended:
- Remove excessive whitespace
- Ensure text is UTF-8 encoded
- Don't remove or modify potential IOCs

### How can I improve extraction quality?

1. Use the validation feature to filter false positives
2. Set an appropriate confidence threshold
3. Fine-tune on domain-specific data if available
4. Use entity type filtering if you only need specific IOC types

### Is the model suitable for production use?

Yes, with the following considerations:
- Validate outputs before taking automated actions
- Set appropriate confidence thresholds
- Monitor false positive/negative rates
- Consider rate limiting for API deployments
- Keep the model and dependencies updated

---

## Security & Ethics

### Is this tool safe to use?

Yes, the tool itself is safe. It only analyzes text to extract IOCs. It does not:
- Connect to or interact with any IOCs
- Execute any code from extracted content
- Send data to external services

### Can this tool be used for malicious purposes?

This tool is intended for **defensive security purposes only**. Use it responsibly for:
- Threat intelligence analysis
- Security monitoring
- Incident response
- Security research

Do not use it for malicious activities.

### How should I handle sensitive data?

- Be cautious when processing text containing sensitive information
- Implement appropriate data retention policies
- Consider anonymizing data before processing if needed
- Log usage appropriately for audit purposes
