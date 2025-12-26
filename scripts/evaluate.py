#!/usr/bin/env python3
"""
ThreatExtract-IOC-NER Evaluation Script

This script evaluates a trained IOC extraction model on a test dataset,
computing precision, recall, F1-score, and other metrics.

Usage:
    python scripts/evaluate.py --model_path ./output/threatextract-ioc-ner/final_model
    python scripts/evaluate.py --model_path ftrout/ThreatExtract-IOC-NER --test_file data/test.json
"""

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import numpy as np
from datasets import Dataset
from seqeval.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    precision_score,
    recall_score,
)
from transformers import (
    AutoModelForTokenClassification,
    AutoTokenizer,
    DataCollatorForTokenClassification,
    Trainer,
    TrainingArguments,
)

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.threatextract.data import IOCDataProcessor
from src.threatextract.labels import ID2LABEL, LABEL2ID, IOC_ENTITY_TYPES

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def compute_metrics_factory(id2label: Dict[int, str]) -> Callable:
    """
    Create a compute_metrics function for the Trainer.

    Args:
        id2label: Mapping from label IDs to label names

    Returns:
        compute_metrics function
    """

    def compute_metrics(eval_preds) -> Dict[str, float]:
        """Compute NER metrics from predictions."""
        predictions, labels = eval_preds
        predictions = np.argmax(predictions, axis=2)

        # Convert to label strings, ignoring special tokens
        true_labels = []
        pred_labels = []

        for prediction, label in zip(predictions, labels):
            true_seq = []
            pred_seq = []

            for pred_id, label_id in zip(prediction, label):
                if label_id == -100:
                    continue
                true_seq.append(id2label[label_id])
                pred_seq.append(id2label[pred_id])

            true_labels.append(true_seq)
            pred_labels.append(pred_seq)

        return {
            "precision": precision_score(true_labels, pred_labels),
            "recall": recall_score(true_labels, pred_labels),
            "f1": f1_score(true_labels, pred_labels),
            "accuracy": accuracy_score(true_labels, pred_labels),
        }

    return compute_metrics


def detailed_evaluation(
    predictions: np.ndarray,
    labels: np.ndarray,
    id2label: Dict[int, str],
) -> Dict[str, Any]:
    """
    Perform detailed evaluation with per-entity metrics.

    Args:
        predictions: Model predictions (batch_size, seq_len, num_labels)
        labels: True labels (batch_size, seq_len)
        id2label: Mapping from label IDs to label names

    Returns:
        Dictionary with detailed metrics
    """
    pred_ids = np.argmax(predictions, axis=2)

    true_labels = []
    pred_labels = []

    for prediction, label in zip(pred_ids, labels):
        true_seq = []
        pred_seq = []

        for pred_id, label_id in zip(prediction, label):
            if label_id == -100:
                continue
            true_seq.append(id2label[label_id])
            pred_seq.append(id2label[pred_id])

        true_labels.append(true_seq)
        pred_labels.append(pred_seq)

    # Get classification report
    report = classification_report(
        true_labels, pred_labels, output_dict=True, zero_division=0
    )

    # Overall metrics
    overall = {
        "precision": precision_score(true_labels, pred_labels),
        "recall": recall_score(true_labels, pred_labels),
        "f1": f1_score(true_labels, pred_labels),
        "accuracy": accuracy_score(true_labels, pred_labels),
    }

    # Per-entity metrics
    per_entity = {}
    for entity_type in IOC_ENTITY_TYPES:
        if entity_type in report:
            per_entity[entity_type] = report[entity_type]
        else:
            per_entity[entity_type] = {
                "precision": 0.0,
                "recall": 0.0,
                "f1-score": 0.0,
                "support": 0,
            }

    return {
        "overall": overall,
        "per_entity": per_entity,
        "classification_report": classification_report(
            true_labels, pred_labels, zero_division=0
        ),
    }


def evaluate_model(
    model_path: str,
    test_file: Optional[str] = None,
    output_file: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Evaluate a trained model on a test dataset.

    Args:
        model_path: Path to the trained model
        test_file: Path to test data file
        output_file: Optional path to save results

    Returns:
        Evaluation results dictionary
    """
    logger.info(f"Loading model from: {model_path}")

    # Load model and tokenizer
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForTokenClassification.from_pretrained(model_path)

    # Get id2label from model config
    id2label = model.config.id2label
    if isinstance(list(id2label.keys())[0], str):
        id2label = {int(k): v for k, v in id2label.items()}

    # Prepare test data
    processor = IOCDataProcessor(tokenizer=tokenizer)

    if test_file and Path(test_file).exists():
        logger.info(f"Loading test data from: {test_file}")
        test_dataset = processor.process_dataset(test_file)
    else:
        # Use synthetic data for demonstration
        logger.warning("No test data provided. Using synthetic data.")
        from src.threatextract.data import create_synthetic_examples

        synthetic_data = create_synthetic_examples(num_examples=100)
        examples = processor.convert_json_to_tokens(synthetic_data)

        for example in examples:
            if isinstance(example["ner_tags"][0], str):
                example["ner_tags"] = [
                    LABEL2ID.get(tag, LABEL2ID["O"]) for tag in example["ner_tags"]
                ]

        full_dataset = Dataset.from_list(examples)
        test_dataset = full_dataset.map(
            processor.tokenize_and_align_labels,
            batched=True,
            remove_columns=full_dataset.column_names,
        )

    logger.info(f"Test dataset size: {len(test_dataset)}")

    # Data collator
    data_collator = DataCollatorForTokenClassification(
        tokenizer=tokenizer, padding=True
    )

    # Create trainer for evaluation
    training_args = TrainingArguments(
        output_dir="./eval_output",
        per_device_eval_batch_size=32,
        do_train=False,
        do_eval=True,
        report_to="none",
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        tokenizer=tokenizer,
        data_collator=data_collator,
        compute_metrics=compute_metrics_factory(id2label),
    )

    # Get predictions
    logger.info("Running evaluation...")
    predictions_output = trainer.predict(test_dataset)

    # Detailed evaluation
    results = detailed_evaluation(
        predictions_output.predictions,
        predictions_output.label_ids,
        id2label,
    )

    # Log results
    logger.info("=" * 60)
    logger.info("EVALUATION RESULTS")
    logger.info("=" * 60)
    logger.info(f"Overall Precision: {results['overall']['precision']:.4f}")
    logger.info(f"Overall Recall:    {results['overall']['recall']:.4f}")
    logger.info(f"Overall F1:        {results['overall']['f1']:.4f}")
    logger.info(f"Overall Accuracy:  {results['overall']['accuracy']:.4f}")
    logger.info("-" * 60)
    logger.info("Per-Entity Results:")
    logger.info("-" * 60)

    for entity_type, metrics in results["per_entity"].items():
        if metrics["support"] > 0:
            logger.info(
                f"  {entity_type:15s} - P: {metrics['precision']:.3f}, "
                f"R: {metrics['recall']:.3f}, "
                f"F1: {metrics['f1-score']:.3f}, "
                f"Support: {metrics['support']}"
            )

    logger.info("=" * 60)
    logger.info("\nFull Classification Report:")
    logger.info(results["classification_report"])

    # Save results
    if output_file:
        with open(output_file, "w") as f:
            json.dump(
                {
                    "overall": results["overall"],
                    "per_entity": results["per_entity"],
                },
                f,
                indent=2,
            )
        logger.info(f"Results saved to: {output_file}")

    return results


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Evaluate ThreatExtract-IOC-NER model"
    )
    parser.add_argument(
        "--model_path",
        type=str,
        required=True,
        help="Path to trained model or HuggingFace model ID",
    )
    parser.add_argument(
        "--test_file",
        type=str,
        default=None,
        help="Path to test data file (JSON or CoNLL format)",
    )
    parser.add_argument(
        "--output_file",
        type=str,
        default=None,
        help="Path to save evaluation results JSON",
    )

    args = parser.parse_args()

    results = evaluate_model(
        model_path=args.model_path,
        test_file=args.test_file,
        output_file=args.output_file,
    )


if __name__ == "__main__":
    main()
