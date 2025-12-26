"""Tests for label definitions."""

import pytest

from src.threatextract.labels import (
    ID2LABEL,
    IOC_ENTITY_TYPES,
    IOC_LABELS,
    LABEL2ID,
    NUM_LABELS,
    get_entity_type,
    get_label_for_entity,
    is_beginning_label,
    is_inside_label,
)


class TestLabelDefinitions:
    """Test label definitions and mappings."""

    def test_label_count(self):
        """Test that label count matches expected (1 O + 2 * entity_types)."""
        expected = 1 + 2 * len(IOC_ENTITY_TYPES)
        assert NUM_LABELS == expected
        assert len(IOC_LABELS) == expected
        assert len(LABEL2ID) == expected
        assert len(ID2LABEL) == expected

    def test_outside_label(self):
        """Test that O label is first."""
        assert IOC_LABELS[0] == "O"
        assert LABEL2ID["O"] == 0
        assert ID2LABEL[0] == "O"

    def test_bio_labels_exist(self):
        """Test that B- and I- labels exist for each entity type."""
        for entity_type in IOC_ENTITY_TYPES:
            b_label = f"B-{entity_type}"
            i_label = f"I-{entity_type}"
            assert b_label in LABEL2ID, f"Missing B label for {entity_type}"
            assert i_label in LABEL2ID, f"Missing I label for {entity_type}"

    def test_label_id_consistency(self):
        """Test that LABEL2ID and ID2LABEL are inverse mappings."""
        for label, idx in LABEL2ID.items():
            assert ID2LABEL[idx] == label

    def test_entity_types(self):
        """Test that expected entity types are present."""
        expected_types = [
            "IPV4", "IPV6", "DOMAIN", "URL", "EMAIL",
            "MD5", "SHA1", "SHA256", "CVE",
            "MALWARE", "THREAT_ACTOR", "CAMPAIGN", "TOOL", "TECHNIQUE",
        ]
        for entity_type in expected_types:
            assert entity_type in IOC_ENTITY_TYPES


class TestLabelFunctions:
    """Test label utility functions."""

    def test_get_entity_type(self):
        """Test extracting entity type from BIO label."""
        assert get_entity_type("O") == "O"
        assert get_entity_type("B-MALWARE") == "MALWARE"
        assert get_entity_type("I-IPV4") == "IPV4"
        assert get_entity_type("B-THREAT_ACTOR") == "THREAT_ACTOR"

    def test_is_beginning_label(self):
        """Test B- label detection."""
        assert is_beginning_label("B-MALWARE") is True
        assert is_beginning_label("B-IPV4") is True
        assert is_beginning_label("I-MALWARE") is False
        assert is_beginning_label("O") is False

    def test_is_inside_label(self):
        """Test I- label detection."""
        assert is_inside_label("I-MALWARE") is True
        assert is_inside_label("I-DOMAIN") is True
        assert is_inside_label("B-MALWARE") is False
        assert is_inside_label("O") is False

    def test_get_label_for_entity(self):
        """Test constructing BIO labels."""
        assert get_label_for_entity("MALWARE", "B") == "B-MALWARE"
        assert get_label_for_entity("IPV4", "I") == "I-IPV4"

    def test_get_label_invalid_entity(self):
        """Test error handling for invalid entity type."""
        with pytest.raises(ValueError):
            get_label_for_entity("INVALID", "B")

    def test_get_label_invalid_position(self):
        """Test error handling for invalid position."""
        with pytest.raises(ValueError):
            get_label_for_entity("MALWARE", "X")
