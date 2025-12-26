"""
IOC Extraction Pipeline Module

High-level pipeline for extracting IOCs from text, providing
additional post-processing, validation, and formatting capabilities.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Union

from src.threatextract.model import ThreatExtractNER
from src.threatextract.labels import IOC_ENTITY_TYPES, ENTITY_COLORS

logger = logging.getLogger(__name__)


@dataclass
class ExtractedIOC:
    """
    Represents an extracted Indicator of Compromise.

    Attributes:
        entity_type: Type of IOC (e.g., 'IPV4', 'MALWARE')
        value: The extracted IOC value
        confidence: Model confidence score (0-1)
        start: Start character position in source text
        end: End character position in source text
        validated: Whether the IOC passed validation
        metadata: Additional metadata about the IOC
    """

    entity_type: str
    value: str
    confidence: float
    start: int
    end: int
    validated: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "entity_type": self.entity_type,
            "value": self.value,
            "confidence": self.confidence,
            "start": self.start,
            "end": self.end,
            "validated": self.validated,
            "metadata": self.metadata,
        }

    def __str__(self) -> str:
        return f"{self.entity_type}: {self.value} (confidence: {self.confidence:.2f})"


class IOCValidator:
    """Validates extracted IOCs using regex patterns and heuristics."""

    # Regex patterns for IOC validation
    PATTERNS = {
        "IPV4": re.compile(
            r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        ),
        "IPV6": re.compile(
            r"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|"
            r"^(?:[0-9a-fA-F]{1,4}:){1,7}:$|"
            r"^(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|"
            r"^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$"
        ),
        "DOMAIN": re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,}$"
        ),
        "URL": re.compile(
            r"^https?://[^\s<>\"{}|\\^`\[\]]+$"
        ),
        "EMAIL": re.compile(
            r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        ),
        "MD5": re.compile(r"^[a-fA-F0-9]{32}$"),
        "SHA1": re.compile(r"^[a-fA-F0-9]{40}$"),
        "SHA256": re.compile(r"^[a-fA-F0-9]{64}$"),
        "CVE": re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE),
    }

    @classmethod
    def validate(cls, entity_type: str, value: str) -> bool:
        """
        Validate an IOC value against known patterns.

        Args:
            entity_type: Type of IOC
            value: Value to validate

        Returns:
            True if valid or no pattern exists, False otherwise
        """
        pattern = cls.PATTERNS.get(entity_type)
        if pattern is None:
            # No validation pattern, assume valid
            return True
        return bool(pattern.match(value.strip()))


class IOCExtractionPipeline:
    """
    High-level pipeline for IOC extraction with validation and formatting.

    This pipeline wraps the NER model and provides additional functionality:
    - IOC validation using regex patterns
    - Deduplication of extracted IOCs
    - Confidence thresholding
    - Multiple output formats

    Example:
        >>> pipeline = IOCExtractionPipeline.from_pretrained("ftrout/ThreatExtract-IOC-NER")
        >>> results = pipeline.extract(
        ...     "The malware at 192.168.1.1 exploited CVE-2023-1234"
        ... )
        >>> for ioc in results:
        ...     print(ioc)
    """

    def __init__(
        self,
        model: ThreatExtractNER,
        validate_iocs: bool = True,
        min_confidence: float = 0.5,
        deduplicate: bool = True,
    ):
        """
        Initialize the pipeline.

        Args:
            model: ThreatExtractNER model instance
            validate_iocs: Whether to validate IOCs using regex
            min_confidence: Minimum confidence threshold (0-1)
            deduplicate: Whether to remove duplicate IOCs
        """
        self.model = model
        self.validate_iocs = validate_iocs
        self.min_confidence = min_confidence
        self.deduplicate = deduplicate
        self.validator = IOCValidator()

    @classmethod
    def from_pretrained(
        cls,
        model_name_or_path: str,
        validate_iocs: bool = True,
        min_confidence: float = 0.5,
        deduplicate: bool = True,
        device: Optional[str] = None,
        **kwargs: Any,
    ) -> "IOCExtractionPipeline":
        """
        Load pipeline from a pre-trained model.

        Args:
            model_name_or_path: HuggingFace model ID or local path
            validate_iocs: Whether to validate IOCs
            min_confidence: Minimum confidence threshold
            deduplicate: Whether to deduplicate results
            device: Device to use for inference
            **kwargs: Additional arguments for model loading

        Returns:
            Initialized pipeline
        """
        model = ThreatExtractNER.from_pretrained(
            model_name_or_path, device=device, **kwargs
        )
        return cls(
            model=model,
            validate_iocs=validate_iocs,
            min_confidence=min_confidence,
            deduplicate=deduplicate,
        )

    def extract(
        self,
        text: Union[str, List[str]],
        entity_types: Optional[List[str]] = None,
        return_dict: bool = False,
    ) -> Union[List[ExtractedIOC], Dict[str, List[ExtractedIOC]]]:
        """
        Extract IOCs from text.

        Args:
            text: Input text or list of texts
            entity_types: Filter to specific entity types (None for all)
            return_dict: If True, group results by entity type

        Returns:
            List of ExtractedIOC objects, or dict grouped by type
        """
        single_input = isinstance(text, str)
        texts = [text] if single_input else text

        all_iocs = []

        for t in texts:
            predictions = self.model.predict(t)
            iocs = self._process_predictions(predictions, entity_types)
            all_iocs.extend(iocs)

        # Deduplicate if enabled
        if self.deduplicate:
            all_iocs = self._deduplicate(all_iocs)

        # Group by type if requested
        if return_dict:
            return self._group_by_type(all_iocs)

        return all_iocs

    def _process_predictions(
        self,
        predictions: List[Dict[str, Any]],
        entity_types: Optional[List[str]],
    ) -> List[ExtractedIOC]:
        """Process raw model predictions into ExtractedIOC objects."""
        iocs = []

        for pred in predictions:
            # Filter by entity type
            if entity_types and pred["entity"] not in entity_types:
                continue

            # Apply confidence threshold
            if pred["score"] < self.min_confidence:
                continue

            # Validate IOC
            validated = True
            if self.validate_iocs:
                validated = self.validator.validate(pred["entity"], pred["word"])

            ioc = ExtractedIOC(
                entity_type=pred["entity"],
                value=pred["word"],
                confidence=pred["score"],
                start=pred["start"],
                end=pred["end"],
                validated=validated,
            )
            iocs.append(ioc)

        return iocs

    def _deduplicate(self, iocs: List[ExtractedIOC]) -> List[ExtractedIOC]:
        """Remove duplicate IOCs, keeping highest confidence."""
        seen: Dict[tuple, ExtractedIOC] = {}

        for ioc in iocs:
            key = (ioc.entity_type, ioc.value.lower())
            if key not in seen or ioc.confidence > seen[key].confidence:
                seen[key] = ioc

        return list(seen.values())

    def _group_by_type(
        self, iocs: List[ExtractedIOC]
    ) -> Dict[str, List[ExtractedIOC]]:
        """Group IOCs by entity type."""
        grouped: Dict[str, List[ExtractedIOC]] = {}

        for ioc in iocs:
            if ioc.entity_type not in grouped:
                grouped[ioc.entity_type] = []
            grouped[ioc.entity_type].append(ioc)

        return grouped

    def extract_to_stix(
        self, text: str
    ) -> Dict[str, Any]:
        """
        Extract IOCs and format as STIX 2.1 bundle (simplified).

        Args:
            text: Input text

        Returns:
            STIX 2.1 bundle dictionary
        """
        iocs = self.extract(text)

        stix_objects = []
        for ioc in iocs:
            stix_obj = self._ioc_to_stix(ioc)
            if stix_obj:
                stix_objects.append(stix_obj)

        return {
            "type": "bundle",
            "id": f"bundle--threatextract",
            "objects": stix_objects,
        }

    def _ioc_to_stix(self, ioc: ExtractedIOC) -> Optional[Dict[str, Any]]:
        """Convert an IOC to STIX indicator."""
        stix_type_mapping = {
            "IPV4": ("ipv4-addr", "value"),
            "IPV6": ("ipv6-addr", "value"),
            "DOMAIN": ("domain-name", "value"),
            "URL": ("url", "value"),
            "EMAIL": ("email-addr", "value"),
            "MD5": ("file", "hashes.MD5"),
            "SHA1": ("file", "hashes.SHA-1"),
            "SHA256": ("file", "hashes.SHA-256"),
        }

        if ioc.entity_type not in stix_type_mapping:
            return None

        stix_type, pattern_prop = stix_type_mapping[ioc.entity_type]
        pattern = f"[{stix_type}:{pattern_prop} = '{ioc.value}']"

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "pattern_type": "stix",
            "pattern": pattern,
            "name": f"{ioc.entity_type}: {ioc.value}",
            "confidence": int(ioc.confidence * 100),
            "labels": ["malicious-activity"],
        }

    def get_summary(self, text: str) -> Dict[str, Any]:
        """
        Get a summary of extracted IOCs.

        Args:
            text: Input text

        Returns:
            Summary dictionary with counts and statistics
        """
        iocs = self.extract(text)
        grouped = self._group_by_type(iocs)

        summary = {
            "total_iocs": len(iocs),
            "by_type": {k: len(v) for k, v in grouped.items()},
            "validated_count": sum(1 for ioc in iocs if ioc.validated),
            "average_confidence": (
                sum(ioc.confidence for ioc in iocs) / len(iocs) if iocs else 0
            ),
            "unique_types": list(grouped.keys()),
        }

        return summary

    def highlight_text(self, text: str) -> str:
        """
        Return text with HTML highlighting of IOCs.

        Args:
            text: Input text

        Returns:
            HTML string with highlighted IOCs
        """
        iocs = self.extract(text)
        # Sort by position (reverse) to replace from end
        iocs.sort(key=lambda x: x.start, reverse=True)

        result = text
        for ioc in iocs:
            color = ENTITY_COLORS.get(ioc.entity_type, "#888888")
            highlighted = (
                f'<span style="background-color: {color}; padding: 2px 4px; '
                f'border-radius: 3px;" title="{ioc.entity_type} '
                f'(confidence: {ioc.confidence:.2f})">'
                f"{ioc.value}</span>"
            )
            result = result[: ioc.start] + highlighted + result[ioc.end :]

        return result
