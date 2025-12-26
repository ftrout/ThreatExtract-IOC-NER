#!/usr/bin/env python3
"""
ThreatExtract-IOC-NER Training Script

This script fine-tunes a transformer model for IOC extraction from
threat intelligence text using Named Entity Recognition.

Usage:
    python scripts/train.py --config configs/training_config.yaml
    python scripts/train.py --base_model bert-base-cased --epochs 5
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import numpy as np
import torch
import yaml
from datasets import DatasetDict
from transformers import (
    AutoConfig,
    AutoModelForTokenClassification,
    AutoTokenizer,
    DataCollatorForTokenClassification,
    EarlyStoppingCallback,
    Trainer,
    TrainingArguments,
    set_seed,
)

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.threatextract.data import IOCDataProcessor, create_synthetic_examples
from src.threatextract.labels import ID2LABEL, LABEL2ID, NUM_LABELS
from scripts.evaluate import compute_metrics_factory

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from YAML file."""
    default_config = {
        "model": {
            "base_model": "microsoft/deberta-v3-base",
            "max_length": 512,
            "label_all_tokens": False,
        },
        "data": {
            "train_file": None,
            "validation_file": None,
            "test_file": None,
            "validation_split": 0.1,
            "format": "auto",
        },
        "training": {
            "output_dir": "./output/threatextract-ioc-ner",
            "num_train_epochs": 10,
            "per_device_train_batch_size": 16,
            "per_device_eval_batch_size": 32,
            "gradient_accumulation_steps": 2,
            "learning_rate": 2e-5,
            "weight_decay": 0.01,
            "warmup_ratio": 0.1,
            "lr_scheduler_type": "cosine",
            "optim": "adamw_torch",
            "max_grad_norm": 1.0,
            "seed": 42,
        },
        "evaluation": {
            "strategy": "epoch",
            "eval_steps": 500,
            "metric_for_best_model": "eval_f1",
            "greater_is_better": True,
            "load_best_model_at_end": True,
        },
        "saving": {
            "strategy": "epoch",
            "save_steps": 500,
            "save_total_limit": 3,
        },
        "logging": {
            "logging_dir": "./output/logs",
            "logging_steps": 100,
            "report_to": "tensorboard",
            "run_name": "threatextract-ioc-ner",
        },
        "hardware": {
            "fp16": True,
            "bf16": False,
            "gradient_checkpointing": False,
            "dataloader_num_workers": 4,
        },
        "early_stopping": {
            "enabled": True,
            "patience": 3,
            "threshold": 0.001,
        },
        "hub": {
            "push_to_hub": False,
            "hub_model_id": None,
            "hub_token": None,
            "private": False,
        },
    }

    if config_path and Path(config_path).exists():
        with open(config_path, "r") as f:
            file_config = yaml.safe_load(f)
            # Deep merge configs
            for section, values in file_config.items():
                if section in default_config and isinstance(values, dict):
                    default_config[section].update(values)
                else:
                    default_config[section] = values

    return default_config


def prepare_data(
    config: Dict[str, Any], tokenizer: AutoTokenizer
) -> DatasetDict:
    """Prepare training data."""
    processor = IOCDataProcessor(
        tokenizer=tokenizer,
        max_length=config["model"]["max_length"],
        label_all_tokens=config["model"]["label_all_tokens"],
    )

    data_config = config["data"]

    # Check if data files exist
    train_file = data_config.get("train_file")
    val_file = data_config.get("validation_file")
    test_file = data_config.get("test_file")

    if train_file and Path(train_file).exists():
        logger.info(f"Loading training data from {train_file}")
        dataset = processor.load_splits(
            train_file=train_file,
            val_file=val_file if val_file and Path(val_file).exists() else None,
            test_file=test_file if test_file and Path(test_file).exists() else None,
            train_val_split=data_config.get("validation_split", 0.1),
        )
    else:
        # Use synthetic data for demonstration
        logger.warning("No training data found. Using synthetic data for demonstration.")
        synthetic_data = create_synthetic_examples(num_examples=500)
        examples = processor.convert_json_to_tokens(synthetic_data)

        # Convert to token IDs
        for example in examples:
            if isinstance(example["ner_tags"][0], str):
                example["ner_tags"] = [
                    LABEL2ID.get(tag, LABEL2ID["O"]) for tag in example["ner_tags"]
                ]

        from datasets import Dataset

        full_dataset = Dataset.from_list(examples)
        tokenized = full_dataset.map(
            processor.tokenize_and_align_labels,
            batched=True,
            remove_columns=full_dataset.column_names,
        )

        split = tokenized.train_test_split(test_size=0.2, seed=42)
        val_test = split["test"].train_test_split(test_size=0.5, seed=42)

        dataset = DatasetDict({
            "train": split["train"],
            "validation": val_test["train"],
            "test": val_test["test"],
        })

    logger.info(f"Dataset prepared: {dataset}")
    return dataset


def train(config: Dict[str, Any]) -> str:
    """
    Main training function.

    Args:
        config: Training configuration dictionary

    Returns:
        Path to the saved model
    """
    # Set seed for reproducibility
    set_seed(config["training"]["seed"])

    # Log configuration
    logger.info("Training configuration:")
    logger.info(f"  Base model: {config['model']['base_model']}")
    logger.info(f"  Epochs: {config['training']['num_train_epochs']}")
    logger.info(f"  Batch size: {config['training']['per_device_train_batch_size']}")
    logger.info(f"  Learning rate: {config['training']['learning_rate']}")

    # Check device
    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info(f"Using device: {device}")

    if device == "cuda":
        logger.info(f"GPU: {torch.cuda.get_device_name(0)}")
        logger.info(f"GPU Memory: {torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB")

    # Load tokenizer
    logger.info(f"Loading tokenizer: {config['model']['base_model']}")
    tokenizer = AutoTokenizer.from_pretrained(config["model"]["base_model"])

    # Prepare data
    dataset = prepare_data(config, tokenizer)

    # Load model
    logger.info(f"Loading model: {config['model']['base_model']}")
    model_config = AutoConfig.from_pretrained(
        config["model"]["base_model"],
        num_labels=NUM_LABELS,
        id2label=ID2LABEL,
        label2id=LABEL2ID,
    )

    model = AutoModelForTokenClassification.from_pretrained(
        config["model"]["base_model"],
        config=model_config,
        ignore_mismatched_sizes=True,
    )

    # Data collator
    data_collator = DataCollatorForTokenClassification(
        tokenizer=tokenizer,
        padding=True,
        max_length=config["model"]["max_length"],
    )

    # Create output directory
    output_dir = Path(config["training"]["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)

    # Training arguments
    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=config["training"]["num_train_epochs"],
        per_device_train_batch_size=config["training"]["per_device_train_batch_size"],
        per_device_eval_batch_size=config["training"]["per_device_eval_batch_size"],
        gradient_accumulation_steps=config["training"]["gradient_accumulation_steps"],
        learning_rate=config["training"]["learning_rate"],
        weight_decay=config["training"]["weight_decay"],
        warmup_ratio=config["training"]["warmup_ratio"],
        lr_scheduler_type=config["training"]["lr_scheduler_type"],
        optim=config["training"]["optim"],
        max_grad_norm=config["training"]["max_grad_norm"],
        seed=config["training"]["seed"],
        # Evaluation
        eval_strategy=config["evaluation"]["strategy"],
        eval_steps=config["evaluation"]["eval_steps"],
        metric_for_best_model=config["evaluation"]["metric_for_best_model"],
        greater_is_better=config["evaluation"]["greater_is_better"],
        load_best_model_at_end=config["evaluation"]["load_best_model_at_end"],
        # Saving
        save_strategy=config["saving"]["strategy"],
        save_steps=config["saving"]["save_steps"],
        save_total_limit=config["saving"]["save_total_limit"],
        # Logging
        logging_dir=config["logging"]["logging_dir"],
        logging_steps=config["logging"]["logging_steps"],
        report_to=config["logging"]["report_to"],
        run_name=config["logging"]["run_name"],
        # Hardware
        fp16=config["hardware"]["fp16"] and device == "cuda",
        bf16=config["hardware"]["bf16"] and device == "cuda",
        gradient_checkpointing=config["hardware"]["gradient_checkpointing"],
        dataloader_num_workers=config["hardware"]["dataloader_num_workers"],
        # Hub
        push_to_hub=config["hub"]["push_to_hub"],
        hub_model_id=config["hub"]["hub_model_id"],
        hub_token=config["hub"]["hub_token"],
        hub_private_repo=config["hub"]["private"],
    )

    # Callbacks
    callbacks = []
    if config["early_stopping"]["enabled"]:
        callbacks.append(
            EarlyStoppingCallback(
                early_stopping_patience=config["early_stopping"]["patience"],
                early_stopping_threshold=config["early_stopping"]["threshold"],
            )
        )

    # Create Trainer
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=dataset["train"],
        eval_dataset=dataset.get("validation"),
        tokenizer=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics_factory(ID2LABEL),
        callbacks=callbacks,
    )

    # Train
    logger.info("Starting training...")
    train_result = trainer.train()

    # Log training results
    logger.info(f"Training completed!")
    logger.info(f"Training loss: {train_result.training_loss:.4f}")

    # Evaluate on test set if available
    if "test" in dataset:
        logger.info("Evaluating on test set...")
        test_results = trainer.evaluate(dataset["test"], metric_key_prefix="test")
        logger.info(f"Test results: {test_results}")

    # Save final model
    final_model_path = output_dir / "final_model"
    trainer.save_model(str(final_model_path))
    tokenizer.save_pretrained(str(final_model_path))
    logger.info(f"Model saved to: {final_model_path}")

    # Save training config
    with open(final_model_path / "training_config.yaml", "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    return str(final_model_path)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Train ThreatExtract-IOC-NER model"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="configs/training_config.yaml",
        help="Path to training configuration file",
    )
    parser.add_argument(
        "--base_model",
        type=str,
        default=None,
        help="Override base model from config",
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=None,
        help="Override number of epochs",
    )
    parser.add_argument(
        "--batch_size",
        type=int,
        default=None,
        help="Override batch size",
    )
    parser.add_argument(
        "--learning_rate",
        type=float,
        default=None,
        help="Override learning rate",
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default=None,
        help="Override output directory",
    )
    parser.add_argument(
        "--train_file",
        type=str,
        default=None,
        help="Override training data file",
    )
    parser.add_argument(
        "--push_to_hub",
        action="store_true",
        help="Push model to HuggingFace Hub",
    )
    parser.add_argument(
        "--hub_model_id",
        type=str,
        default=None,
        help="HuggingFace Hub model ID",
    )

    args = parser.parse_args()

    # Load config
    config = load_config(args.config)

    # Override config with command line arguments
    if args.base_model:
        config["model"]["base_model"] = args.base_model
    if args.epochs:
        config["training"]["num_train_epochs"] = args.epochs
    if args.batch_size:
        config["training"]["per_device_train_batch_size"] = args.batch_size
    if args.learning_rate:
        config["training"]["learning_rate"] = args.learning_rate
    if args.output_dir:
        config["training"]["output_dir"] = args.output_dir
    if args.train_file:
        config["data"]["train_file"] = args.train_file
    if args.push_to_hub:
        config["hub"]["push_to_hub"] = True
    if args.hub_model_id:
        config["hub"]["hub_model_id"] = args.hub_model_id

    # Run training
    model_path = train(config)
    logger.info(f"Training complete! Model saved to: {model_path}")


if __name__ == "__main__":
    main()
