"""
ThreatExtract NER Model Module

This module provides the core model class for IOC extraction using
token classification with transformer-based models.
"""

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import torch
from transformers import (
    AutoConfig,
    AutoModelForTokenClassification,
    AutoTokenizer,
    PreTrainedModel,
    PreTrainedTokenizer,
    PreTrainedTokenizerFast,
)

from src.threatextract.labels import ID2LABEL, LABEL2ID, NUM_LABELS

logger = logging.getLogger(__name__)


class ThreatExtractNER:
    """
    ThreatExtract NER model for extracting IOCs from threat intelligence text.

    This class wraps a transformer-based token classification model specifically
    configured for Indicator of Compromise (IOC) extraction.

    Attributes:
        model: The underlying transformer model
        tokenizer: The tokenizer for text processing
        device: The device (CPU/GPU) for inference
        config: Model configuration

    Example:
        >>> from src.threatextract import ThreatExtractNER
        >>> ner = ThreatExtractNER.from_pretrained("fmt0816/ThreatExtract-IOC-NER")
        >>> results = ner.predict("The malware connected to 192.168.1.1")
        >>> print(results)
    """

    # Supported base models for fine-tuning
    SUPPORTED_BASE_MODELS = [
        "bert-base-uncased",
        "bert-base-cased",
        "bert-large-uncased",
        "bert-large-cased",
        "microsoft/deberta-v3-base",
        "microsoft/deberta-v3-large",
        "roberta-base",
        "roberta-large",
        "distilbert-base-uncased",
        "distilbert-base-cased",
        "allenai/scibert_scivocab_uncased",
        "jackaduma/SecBERT",
    ]

    def __init__(
        self,
        model: PreTrainedModel,
        tokenizer: Union[PreTrainedTokenizer, PreTrainedTokenizerFast],
        device: Optional[str] = None,
    ):
        """
        Initialize ThreatExtractNER with a pre-trained model.

        Args:
            model: Pre-trained token classification model
            tokenizer: Tokenizer compatible with the model
            device: Device to use ('cuda', 'cpu', or None for auto-detect)
        """
        self.model = model
        self.tokenizer = tokenizer

        if device is None:
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        else:
            self.device = device

        self.model.to(self.device)
        self.model.eval()
        logger.info(f"Model loaded on device: {self.device}")

    @classmethod
    def from_pretrained(
        cls,
        model_name_or_path: Union[str, Path],
        device: Optional[str] = None,
        **kwargs: Any,
    ) -> "ThreatExtractNER":
        """
        Load a pre-trained ThreatExtract NER model.

        Args:
            model_name_or_path: HuggingFace model ID or local path
            device: Device to use ('cuda', 'cpu', or None for auto-detect)
            **kwargs: Additional arguments passed to from_pretrained

        Returns:
            Initialized ThreatExtractNER instance

        Example:
            >>> ner = ThreatExtractNER.from_pretrained("fmt0816/ThreatExtract-IOC-NER")
        """
        logger.info(f"Loading model from: {model_name_or_path}")

        tokenizer = AutoTokenizer.from_pretrained(model_name_or_path, **kwargs)
        model = AutoModelForTokenClassification.from_pretrained(
            model_name_or_path, **kwargs
        )

        return cls(model=model, tokenizer=tokenizer, device=device)

    @classmethod
    def from_base_model(
        cls,
        base_model_name: str = "microsoft/deberta-v3-base",
        device: Optional[str] = None,
        **kwargs: Any,
    ) -> "ThreatExtractNER":
        """
        Initialize a new model from a base transformer for fine-tuning.

        Args:
            base_model_name: Name of the base model to use
            device: Device to use ('cuda', 'cpu', or None for auto-detect)
            **kwargs: Additional arguments passed to from_pretrained

        Returns:
            ThreatExtractNER instance ready for fine-tuning

        Example:
            >>> ner = ThreatExtractNER.from_base_model("microsoft/deberta-v3-base")
        """
        logger.info(f"Initializing from base model: {base_model_name}")

        config = AutoConfig.from_pretrained(
            base_model_name,
            num_labels=NUM_LABELS,
            id2label=ID2LABEL,
            label2id=LABEL2ID,
            **kwargs,
        )

        tokenizer = AutoTokenizer.from_pretrained(base_model_name, **kwargs)
        model = AutoModelForTokenClassification.from_pretrained(
            base_model_name, config=config, ignore_mismatched_sizes=True, **kwargs
        )

        return cls(model=model, tokenizer=tokenizer, device=device)

    def predict(
        self,
        text: Union[str, List[str]],
        batch_size: int = 8,
        aggregation_strategy: str = "simple",
    ) -> Union[List[Dict[str, Any]], List[List[Dict[str, Any]]]]:
        """
        Extract IOCs from text using NER.

        Args:
            text: Input text or list of texts
            batch_size: Batch size for processing multiple texts
            aggregation_strategy: How to aggregate subword tokens
                - 'simple': Use first subword prediction
                - 'average': Average subword predictions
                - 'max': Use max confidence prediction

        Returns:
            List of extracted entities with:
                - entity: Entity type (e.g., 'MALWARE', 'IPV4')
                - word: The extracted text
                - score: Confidence score
                - start: Start character position
                - end: End character position

        Example:
            >>> results = ner.predict("APT29 used Cobalt Strike to attack 10.0.0.1")
            >>> for entity in results:
            ...     print(f"{entity['entity']}: {entity['word']}")
        """
        single_input = isinstance(text, str)
        texts = [text] if single_input else text

        all_results = []

        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i : i + batch_size]
            batch_results = self._predict_batch(batch_texts, aggregation_strategy)
            all_results.extend(batch_results)

        return all_results[0] if single_input else all_results

    def _predict_batch(
        self, texts: List[str], aggregation_strategy: str
    ) -> List[List[Dict[str, Any]]]:
        """Process a batch of texts."""
        encodings = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt",
            return_offsets_mapping=True,
        )

        offset_mapping = encodings.pop("offset_mapping")
        encodings = {k: v.to(self.device) for k, v in encodings.items()}

        with torch.no_grad():
            outputs = self.model(**encodings)

        predictions = torch.argmax(outputs.logits, dim=-1)
        scores = torch.softmax(outputs.logits, dim=-1)

        batch_results = []

        for idx, text in enumerate(texts):
            results = self._extract_entities(
                text,
                predictions[idx].cpu().numpy(),
                scores[idx].cpu().numpy(),
                offset_mapping[idx].cpu().numpy(),
                encodings["input_ids"][idx].cpu().numpy(),
                aggregation_strategy,
            )
            batch_results.append(results)

        return batch_results

    def _extract_entities(
        self,
        text: str,
        predictions: Any,
        scores: Any,
        offset_mapping: Any,
        input_ids: Any,
        aggregation_strategy: str,
    ) -> List[Dict[str, Any]]:
        """Extract entities from model predictions."""
        entities = []
        current_entity = None

        for idx, (pred_id, offset) in enumerate(zip(predictions, offset_mapping)):
            # Skip special tokens
            if offset[0] == 0 and offset[1] == 0:
                if current_entity is not None:
                    entities.append(current_entity)
                    current_entity = None
                continue

            label = ID2LABEL[pred_id]
            score = float(scores[idx][pred_id])

            if label == "O":
                if current_entity is not None:
                    entities.append(current_entity)
                    current_entity = None
            elif label.startswith("B-"):
                if current_entity is not None:
                    entities.append(current_entity)

                entity_type = label[2:]
                current_entity = {
                    "entity": entity_type,
                    "word": text[offset[0] : offset[1]],
                    "score": score,
                    "start": int(offset[0]),
                    "end": int(offset[1]),
                    "scores": [score],
                }
            elif label.startswith("I-"):
                entity_type = label[2:]
                if current_entity is not None and current_entity["entity"] == entity_type:
                    # Continue current entity
                    current_entity["word"] = text[
                        current_entity["start"] : offset[1]
                    ]
                    current_entity["end"] = int(offset[1])
                    current_entity["scores"].append(score)

                    # Update aggregate score
                    if aggregation_strategy == "average":
                        current_entity["score"] = sum(current_entity["scores"]) / len(
                            current_entity["scores"]
                        )
                    elif aggregation_strategy == "max":
                        current_entity["score"] = max(current_entity["scores"])
                    # 'simple' keeps first score
                else:
                    # I- without matching B-, treat as new entity
                    if current_entity is not None:
                        entities.append(current_entity)
                    current_entity = {
                        "entity": entity_type,
                        "word": text[offset[0] : offset[1]],
                        "score": score,
                        "start": int(offset[0]),
                        "end": int(offset[1]),
                        "scores": [score],
                    }

        if current_entity is not None:
            entities.append(current_entity)

        # Clean up temporary scores list
        for entity in entities:
            del entity["scores"]

        return entities

    def save_pretrained(
        self,
        save_directory: Union[str, Path],
        push_to_hub: bool = False,
        **kwargs: Any,
    ) -> None:
        """
        Save the model and tokenizer to a directory.

        Args:
            save_directory: Directory to save the model
            push_to_hub: Whether to push to HuggingFace Hub
            **kwargs: Additional arguments for save_pretrained
        """
        save_directory = Path(save_directory)
        save_directory.mkdir(parents=True, exist_ok=True)

        self.model.save_pretrained(
            save_directory, push_to_hub=push_to_hub, **kwargs
        )
        self.tokenizer.save_pretrained(
            save_directory, push_to_hub=push_to_hub, **kwargs
        )

        logger.info(f"Model saved to: {save_directory}")

    def get_model_info(self) -> Dict[str, Any]:
        """Get model information and configuration."""
        return {
            "model_type": self.model.config.model_type,
            "num_labels": self.model.config.num_labels,
            "num_parameters": sum(p.numel() for p in self.model.parameters()),
            "trainable_parameters": sum(
                p.numel() for p in self.model.parameters() if p.requires_grad
            ),
            "device": str(self.device),
            "labels": list(LABEL2ID.keys()),
        }
