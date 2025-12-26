"""
ThreatExtract-IOC-NER: Named Entity Recognition for Threat Intelligence IOC Extraction

A fine-tuned transformer model for extracting Indicators of Compromise (IOCs)
from cybersecurity threat intelligence text.
"""

__version__ = "1.0.0"
__author__ = "ThreatExtract Team"

from src.threatextract.model import ThreatExtractNER
from src.threatextract.pipeline import IOCExtractionPipeline
from src.threatextract.labels import IOC_LABELS, LABEL2ID, ID2LABEL

__all__ = [
    "ThreatExtractNER",
    "IOCExtractionPipeline",
    "IOC_LABELS",
    "LABEL2ID",
    "ID2LABEL",
]
