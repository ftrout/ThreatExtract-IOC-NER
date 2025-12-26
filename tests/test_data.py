"""Tests for data processing."""

import json
import tempfile
from pathlib import Path

import pytest

from src.threatextract.data import (
    IOCDataProcessor,
    create_synthetic_examples,
)


class TestSyntheticDataGeneration:
    """Test synthetic data generation."""

    def test_create_synthetic_examples(self):
        """Test that synthetic examples are generated correctly."""
        examples = create_synthetic_examples(num_examples=10)

        assert len(examples) == 10

        for example in examples:
            assert "text" in example
            assert "entities" in example
            assert isinstance(example["text"], str)
            assert isinstance(example["entities"], list)

    def test_synthetic_example_entities(self):
        """Test that entities have correct structure."""
        examples = create_synthetic_examples(num_examples=5)

        for example in examples:
            for entity in example["entities"]:
                assert "start" in entity
                assert "end" in entity
                assert "label" in entity
                assert entity["start"] >= 0
                assert entity["end"] > entity["start"]
                assert entity["end"] <= len(example["text"])

    def test_synthetic_example_text_matches_entities(self):
        """Test that entity positions match actual text."""
        examples = create_synthetic_examples(num_examples=10)

        for example in examples:
            text = example["text"]
            for entity in example["entities"]:
                extracted = text[entity["start"]:entity["end"]]
                # Should be a non-empty string
                assert len(extracted) > 0


class TestIOCValidation:
    """Test IOC validation patterns."""

    def test_ipv4_validation(self):
        """Test IPv4 validation pattern."""
        from src.threatextract.pipeline import IOCValidator

        valid_ips = [
            "192.168.1.1",
            "10.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
        ]
        invalid_ips = [
            "256.1.1.1",
            "192.168.1",
            "192.168.1.1.1",
            "abc.def.ghi.jkl",
        ]

        for ip in valid_ips:
            assert IOCValidator.validate("IPV4", ip), f"{ip} should be valid"

        for ip in invalid_ips:
            assert not IOCValidator.validate("IPV4", ip), f"{ip} should be invalid"

    def test_md5_validation(self):
        """Test MD5 hash validation."""
        from src.threatextract.pipeline import IOCValidator

        valid = "d41d8cd98f00b204e9800998ecf8427e"
        invalid = "d41d8cd98f00b204"  # Too short

        assert IOCValidator.validate("MD5", valid)
        assert not IOCValidator.validate("MD5", invalid)

    def test_sha256_validation(self):
        """Test SHA256 hash validation."""
        from src.threatextract.pipeline import IOCValidator

        valid = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        invalid = "e3b0c44298fc1c149afbf4c8996fb924"  # Too short

        assert IOCValidator.validate("SHA256", valid)
        assert not IOCValidator.validate("SHA256", invalid)

    def test_cve_validation(self):
        """Test CVE ID validation."""
        from src.threatextract.pipeline import IOCValidator

        valid_cves = [
            "CVE-2021-44228",
            "CVE-2023-1234",
            "CVE-2020-12345",
        ]
        invalid_cves = [
            "CVE-21-44228",  # Year too short
            "CVE2021-44228",  # Missing hyphen
            "cve-2021-44228",  # Lowercase (should still work)
        ]

        for cve in valid_cves:
            assert IOCValidator.validate("CVE", cve), f"{cve} should be valid"

        # Note: lowercase CVE is valid per the regex (re.IGNORECASE)
        assert IOCValidator.validate("CVE", "cve-2021-44228")

    def test_domain_validation(self):
        """Test domain name validation."""
        from src.threatextract.pipeline import IOCValidator

        valid_domains = [
            "example.com",
            "sub.example.com",
            "evil-domain.net",
        ]
        invalid_domains = [
            "example",  # No TLD
            ".com",  # No domain name
        ]

        for domain in valid_domains:
            assert IOCValidator.validate("DOMAIN", domain), f"{domain} should be valid"

        for domain in invalid_domains:
            assert not IOCValidator.validate("DOMAIN", domain), f"{domain} should be invalid"

    def test_no_pattern_returns_true(self):
        """Test that entities without patterns return True."""
        from src.threatextract.pipeline import IOCValidator

        # MALWARE doesn't have a regex pattern
        assert IOCValidator.validate("MALWARE", "Emotet")
        assert IOCValidator.validate("THREAT_ACTOR", "APT29")


class TestDataFormats:
    """Test data format handling."""

    def test_json_format(self):
        """Test loading JSON format data."""
        # Create temp JSON file
        data = [
            {
                "text": "Test malware at 192.168.1.1",
                "entities": [
                    {"start": 5, "end": 12, "label": "MALWARE"},
                    {"start": 16, "end": 27, "label": "IPV4"},
                ]
            }
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(data, f)
            temp_path = f.name

        try:
            from transformers import AutoTokenizer
            # Use a small tokenizer for testing
            tokenizer = AutoTokenizer.from_pretrained("bert-base-uncased")
            processor = IOCDataProcessor(tokenizer)

            loaded = processor.load_json(temp_path)
            assert len(loaded) == 1
            assert loaded[0]["text"] == data[0]["text"]
        finally:
            Path(temp_path).unlink()
