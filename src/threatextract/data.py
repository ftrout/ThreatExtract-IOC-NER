"""
Data Processing Module for ThreatExtract-IOC-NER

This module handles loading, preprocessing, and tokenizing training data
for the IOC extraction NER model.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import numpy as np
from datasets import Dataset, DatasetDict, load_dataset
from transformers import PreTrainedTokenizer, PreTrainedTokenizerFast

from src.threatextract.labels import LABEL2ID, IOC_LABELS

logger = logging.getLogger(__name__)


class IOCDataProcessor:
    """
    Data processor for IOC NER training data.

    Handles multiple input formats:
    - CoNLL format (token label pairs)
    - JSON format (text with entity spans)
    - Hugging Face datasets format

    Example:
        >>> processor = IOCDataProcessor(tokenizer)
        >>> dataset = processor.load_and_process("data/train.json")
    """

    def __init__(
        self,
        tokenizer: Union[PreTrainedTokenizer, PreTrainedTokenizerFast],
        max_length: int = 512,
        label_all_tokens: bool = False,
    ):
        """
        Initialize the data processor.

        Args:
            tokenizer: HuggingFace tokenizer
            max_length: Maximum sequence length
            label_all_tokens: Whether to label all subword tokens
        """
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.label_all_tokens = label_all_tokens

    def load_json(self, file_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """
        Load data from JSON file.

        Expected format:
        [
            {
                "text": "The malware connected to 192.168.1.1",
                "entities": [
                    {"start": 25, "end": 36, "label": "IPV4"}
                ]
            }
        ]
        """
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.info(f"Loaded {len(data)} examples from {file_path}")
        return data

    def load_conll(self, file_path: Union[str, Path]) -> List[Dict[str, Any]]:
        """
        Load data from CoNLL format file.

        Expected format (space or tab separated):
        Token Label
        The O
        malware B-MALWARE
        connected O
        ...
        (blank line between sentences)
        """
        examples = []
        current_tokens = []
        current_labels = []

        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    if current_tokens:
                        examples.append({
                            "tokens": current_tokens,
                            "ner_tags": current_labels,
                        })
                        current_tokens = []
                        current_labels = []
                else:
                    parts = line.split()
                    if len(parts) >= 2:
                        current_tokens.append(parts[0])
                        current_labels.append(parts[-1])

            # Don't forget last example
            if current_tokens:
                examples.append({
                    "tokens": current_tokens,
                    "ner_tags": current_labels,
                })

        logger.info(f"Loaded {len(examples)} examples from {file_path}")
        return examples

    def convert_json_to_tokens(
        self, examples: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Convert JSON format (text + spans) to token format.

        Args:
            examples: List of examples with 'text' and 'entities' keys

        Returns:
            List of examples with 'tokens' and 'ner_tags' keys
        """
        converted = []

        for example in examples:
            text = example["text"]
            entities = sorted(example.get("entities", []), key=lambda x: x["start"])

            tokens = []
            labels = []
            current_pos = 0

            for entity in entities:
                # Add tokens before entity
                if current_pos < entity["start"]:
                    before_text = text[current_pos : entity["start"]]
                    for word in before_text.split():
                        tokens.append(word)
                        labels.append("O")

                # Add entity tokens
                entity_text = text[entity["start"] : entity["end"]]
                entity_words = entity_text.split()
                for i, word in enumerate(entity_words):
                    tokens.append(word)
                    if i == 0:
                        labels.append(f"B-{entity['label']}")
                    else:
                        labels.append(f"I-{entity['label']}")

                current_pos = entity["end"]

            # Add remaining tokens
            if current_pos < len(text):
                remaining_text = text[current_pos:]
                for word in remaining_text.split():
                    tokens.append(word)
                    labels.append("O")

            converted.append({
                "tokens": tokens,
                "ner_tags": labels,
            })

        return converted

    def tokenize_and_align_labels(
        self, examples: Dict[str, List]
    ) -> Dict[str, List]:
        """
        Tokenize text and align labels with subword tokens.

        This function handles the alignment of labels when tokens are
        split into subwords by the tokenizer.

        Args:
            examples: Batch of examples with 'tokens' and 'ner_tags'

        Returns:
            Tokenized examples with aligned labels
        """
        tokenized_inputs = self.tokenizer(
            examples["tokens"],
            truncation=True,
            max_length=self.max_length,
            is_split_into_words=True,
            padding=False,
        )

        labels = []
        for i, label_list in enumerate(examples["ner_tags"]):
            word_ids = tokenized_inputs.word_ids(batch_index=i)
            previous_word_idx = None
            label_ids = []

            for word_idx in word_ids:
                if word_idx is None:
                    # Special tokens get -100
                    label_ids.append(-100)
                elif word_idx != previous_word_idx:
                    # First token of a word
                    label = label_list[word_idx]
                    label_id = LABEL2ID.get(label, LABEL2ID["O"])
                    label_ids.append(label_id)
                else:
                    # Continuation of a word (subword)
                    if self.label_all_tokens:
                        label = label_list[word_idx]
                        # Convert B- to I- for continuation
                        if label.startswith("B-"):
                            label = "I-" + label[2:]
                        label_id = LABEL2ID.get(label, LABEL2ID["O"])
                        label_ids.append(label_id)
                    else:
                        label_ids.append(-100)

                previous_word_idx = word_idx

            labels.append(label_ids)

        tokenized_inputs["labels"] = labels
        return tokenized_inputs

    def process_dataset(
        self,
        data: Union[str, Path, List[Dict]],
        format: str = "auto",
    ) -> Dataset:
        """
        Process data into a HuggingFace Dataset.

        Args:
            data: File path or list of examples
            format: 'json', 'conll', or 'auto' (detect from extension)

        Returns:
            Processed HuggingFace Dataset
        """
        if isinstance(data, (str, Path)):
            data = Path(data)
            if format == "auto":
                format = "json" if data.suffix == ".json" else "conll"

            if format == "json":
                examples = self.load_json(data)
                examples = self.convert_json_to_tokens(examples)
            else:
                examples = self.load_conll(data)
        else:
            examples = data

        # Convert labels to IDs
        for example in examples:
            if isinstance(example["ner_tags"][0], str):
                example["ner_tags"] = [
                    LABEL2ID.get(tag, LABEL2ID["O"])
                    for tag in example["ner_tags"]
                ]

        dataset = Dataset.from_list(examples)

        # Tokenize and align labels
        tokenized_dataset = dataset.map(
            self.tokenize_and_align_labels,
            batched=True,
            remove_columns=dataset.column_names,
            desc="Tokenizing dataset",
        )

        return tokenized_dataset

    def load_splits(
        self,
        train_file: Optional[Union[str, Path]] = None,
        val_file: Optional[Union[str, Path]] = None,
        test_file: Optional[Union[str, Path]] = None,
        train_val_split: float = 0.1,
    ) -> DatasetDict:
        """
        Load and process train/validation/test splits.

        Args:
            train_file: Path to training data
            val_file: Path to validation data (optional)
            test_file: Path to test data (optional)
            train_val_split: Fraction for validation if no val_file

        Returns:
            DatasetDict with train, validation, and test splits
        """
        splits = {}

        if train_file:
            train_dataset = self.process_dataset(train_file)

            if val_file is None and train_val_split > 0:
                # Create validation split from training data
                split_dataset = train_dataset.train_test_split(
                    test_size=train_val_split, seed=42
                )
                splits["train"] = split_dataset["train"]
                splits["validation"] = split_dataset["test"]
            else:
                splits["train"] = train_dataset

        if val_file:
            splits["validation"] = self.process_dataset(val_file)

        if test_file:
            splits["test"] = self.process_dataset(test_file)

        return DatasetDict(splits)


def create_synthetic_examples(num_examples: int = 100) -> List[Dict[str, Any]]:
    """
    Create synthetic training examples for demonstration.

    This function generates synthetic threat intelligence text with
    labeled IOCs for training and testing purposes.

    Args:
        num_examples: Number of examples to generate

    Returns:
        List of examples in JSON format
    """
    import random

    templates = [
        "The {MALWARE} malware was observed communicating with {IPV4}.",
        "Analysis reveals connections to {DOMAIN} using {TOOL}.",
        "{THREAT_ACTOR} exploited {CVE} to deploy {MALWARE}.",
        "Indicators include: IP {IPV4}, hash {SHA256}.",
        "The campaign {CAMPAIGN} used {URL} for C2 communication.",
        "Malicious file {FILE_NAME} connects to {IPV4} and {DOMAIN}.",
        "{THREAT_ACTOR} leveraged {TECHNIQUE} technique ({CVE}).",
        "Registry key {REGISTRY_KEY} modified by {MALWARE}.",
        "Email from {EMAIL} contained {FILE_NAME} with hash {MD5}.",
        "Attack originated from {IPV4} targeting {DOMAIN}.",
    ]

    samples = {
        "MALWARE": ["Emotet", "TrickBot", "Ryuk", "Cobalt Strike", "WannaCry",
                    "NotPetya", "Dridex", "QakBot", "IcedID", "Raccoon Stealer"],
        "THREAT_ACTOR": ["APT29", "Lazarus Group", "APT28", "FIN7", "Turla",
                        "Carbanak", "APT41", "DarkSide", "REvil", "Conti"],
        "TOOL": ["Mimikatz", "Cobalt Strike", "Metasploit", "Empire", "BloodHound",
                "SharpHound", "PSExec", "Covenant", "CrackMapExec", "Impacket"],
        "IPV4": ["192.168.1.100", "10.0.0.55", "172.16.0.1", "45.33.32.156",
                "198.51.100.1", "203.0.113.50", "185.220.101.1", "91.219.28.45"],
        "DOMAIN": ["evil-domain.com", "malware-c2.net", "bad-actor.org",
                   "phishing-site.com", "data-exfil.net", "backdoor.io"],
        "CVE": ["CVE-2023-1234", "CVE-2022-5678", "CVE-2021-44228",
               "CVE-2020-0796", "CVE-2019-19781", "CVE-2023-34362"],
        "SHA256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                   "a948904f2f0f479b8f8564cbf12dac6b0f3d6b9b81c3b2a5e7b3f5e3c2d1a0b9"],
        "MD5": ["d41d8cd98f00b204e9800998ecf8427e", "098f6bcd4621d373cade4e832627b4f6"],
        "URL": ["https://evil.com/payload.exe", "http://malware.net/dropper",
               "https://phishing.com/login", "http://c2-server.net/beacon"],
        "EMAIL": ["attacker@malicious.com", "phisher@evil-domain.net",
                 "spam@bad-actor.org"],
        "FILE_NAME": ["payload.exe", "dropper.dll", "malware.doc", "exploit.pdf"],
        "CAMPAIGN": ["Operation Aurora", "SolarWinds", "NotPetya Campaign",
                    "WannaCry Attack", "Operation Sharpshooter"],
        "TECHNIQUE": ["T1059", "T1566", "T1078", "T1105", "T1027", "Spearphishing",
                     "Credential Dumping", "Lateral Movement"],
        "REGISTRY_KEY": ["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                        "HKCU\\Software\\Classes\\mscfile\\shell\\open\\command"],
    }

    examples = []
    for _ in range(num_examples):
        template = random.choice(templates)
        text = template
        entities = []

        # Find and replace placeholders
        import re
        for match in re.finditer(r"\{(\w+)\}", template):
            entity_type = match.group(1)
            if entity_type in samples:
                value = random.choice(samples[entity_type])
                # Find position in current text
                placeholder = "{" + entity_type + "}"
                start = text.find(placeholder)
                if start != -1:
                    end = start + len(value)
                    text = text.replace(placeholder, value, 1)
                    entities.append({
                        "start": start,
                        "end": end,
                        "label": entity_type,
                    })

        examples.append({
            "text": text,
            "entities": entities,
        })

    return examples
