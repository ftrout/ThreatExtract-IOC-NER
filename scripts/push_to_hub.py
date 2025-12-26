#!/usr/bin/env python3
"""
Push ThreatExtract-IOC-NER Model to Hugging Face Hub

This script uploads a trained model to the Hugging Face Hub with all
necessary files and metadata.

Usage:
    python scripts/push_to_hub.py --model_path ./output/threatextract-ioc-ner/final_model
    python scripts/push_to_hub.py --model_path ./output/final_model --hub_id username/model-name
"""

import argparse
import logging
import shutil
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def push_to_hub(
    model_path: str,
    hub_model_id: str,
    private: bool = False,
    commit_message: str = "Upload ThreatExtract-IOC-NER model",
) -> str:
    """
    Push a trained model to Hugging Face Hub.

    Args:
        model_path: Path to the trained model directory
        hub_model_id: Hugging Face Hub model ID (e.g., "username/ThreatExtract-IOC-NER")
        private: Whether to make the repo private
        commit_message: Commit message for the upload

    Returns:
        URL of the uploaded model
    """
    try:
        from huggingface_hub import HfApi, login
        from transformers import AutoModelForTokenClassification, AutoTokenizer
    except ImportError:
        logger.error("Please install huggingface_hub: pip install huggingface_hub")
        sys.exit(1)

    model_path = Path(model_path)

    if not model_path.exists():
        logger.error(f"Model path does not exist: {model_path}")
        sys.exit(1)

    logger.info(f"Loading model from: {model_path}")

    # Load model and tokenizer
    model = AutoModelForTokenClassification.from_pretrained(model_path)
    tokenizer = AutoTokenizer.from_pretrained(model_path)

    logger.info(f"Pushing to Hub: {hub_model_id}")

    # Push model and tokenizer
    model.push_to_hub(
        hub_model_id,
        private=private,
        commit_message=commit_message,
    )
    tokenizer.push_to_hub(
        hub_model_id,
        private=private,
        commit_message=commit_message,
    )

    # Copy and push MODEL_CARD.md as README.md if it exists
    project_root = Path(__file__).parent.parent
    model_card_path = project_root / "MODEL_CARD.md"

    if model_card_path.exists():
        api = HfApi()
        api.upload_file(
            path_or_fileobj=str(model_card_path),
            path_in_repo="README.md",
            repo_id=hub_model_id,
            commit_message="Add model card",
        )
        logger.info("Uploaded MODEL_CARD.md as README.md")

    url = f"https://huggingface.co/{hub_model_id}"
    logger.info(f"Model successfully uploaded to: {url}")

    return url


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Push ThreatExtract-IOC-NER model to Hugging Face Hub"
    )
    parser.add_argument(
        "--model_path",
        type=str,
        required=True,
        help="Path to the trained model directory",
    )
    parser.add_argument(
        "--hub_id",
        type=str,
        default="ftrout/ThreatExtract-IOC-NER",
        help="Hugging Face Hub model ID",
    )
    parser.add_argument(
        "--private",
        action="store_true",
        help="Make the repository private",
    )
    parser.add_argument(
        "--message",
        type=str,
        default="Upload ThreatExtract-IOC-NER model",
        help="Commit message",
    )

    args = parser.parse_args()

    # Check for HF token
    import os
    if not os.environ.get("HF_TOKEN") and not os.environ.get("HUGGING_FACE_HUB_TOKEN"):
        logger.warning(
            "No Hugging Face token found. Set HF_TOKEN environment variable "
            "or run `huggingface-cli login` first."
        )

    push_to_hub(
        model_path=args.model_path,
        hub_model_id=args.hub_id,
        private=args.private,
        commit_message=args.message,
    )


if __name__ == "__main__":
    main()
