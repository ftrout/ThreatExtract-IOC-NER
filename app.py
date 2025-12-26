#!/usr/bin/env python3
"""
ThreatExtract-IOC-NER Gradio Demo

A web-based demo for extracting Indicators of Compromise (IOCs)
from threat intelligence text using the ThreatExtract NER model.

Usage:
    python app.py
    python app.py --model_path ./output/threatextract-ioc-ner/final_model
    python app.py --share  # Create a public shareable link
"""

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import gradio as gr

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Entity colors for highlighting
ENTITY_COLORS = {
    "IPV4": "#FF6B6B",
    "IPV6": "#FF8E8E",
    "DOMAIN": "#4ECDC4",
    "URL": "#45B7B8",
    "EMAIL": "#96CEB4",
    "MD5": "#DDA0DD",
    "SHA1": "#E6B0E6",
    "SHA256": "#F0C0F0",
    "CVE": "#FFE66D",
    "MALWARE": "#FF4757",
    "THREAT_ACTOR": "#5352ED",
    "CAMPAIGN": "#3742FA",
    "TOOL": "#FFA502",
    "TECHNIQUE": "#FF7F50",
    "REGISTRY_KEY": "#A8E6CF",
    "FILE_PATH": "#88D8B0",
    "FILE_NAME": "#B8E6CF",
}

# Global model variable
model = None


def load_model(model_path: str):
    """Load the NER model."""
    global model
    try:
        from src.threatextract.pipeline import IOCExtractionPipeline

        logger.info(f"Loading model from: {model_path}")
        model = IOCExtractionPipeline.from_pretrained(
            model_path,
            validate_iocs=True,
            min_confidence=0.5,
            deduplicate=True,
        )
        logger.info("Model loaded successfully!")
        return True
    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return False


def extract_iocs(
    text: str,
    min_confidence: float = 0.5,
    validate: bool = True,
    selected_types: List[str] = None,
) -> Tuple[str, str, str]:
    """
    Extract IOCs from text and return formatted results.

    Args:
        text: Input text
        min_confidence: Minimum confidence threshold
        validate: Whether to validate IOCs
        selected_types: Entity types to extract (None for all)

    Returns:
        Tuple of (highlighted_text, ioc_table, json_output)
    """
    if model is None:
        return (
            "⚠️ Model not loaded. Please check the model path.",
            "No model loaded",
            "{}",
        )

    if not text.strip():
        return "", "No text provided", "{}"

    try:
        # Update pipeline settings
        model.min_confidence = min_confidence
        model.validate_iocs = validate

        # Extract IOCs
        iocs = model.extract(text, entity_types=selected_types)

        if not iocs:
            return text, "No IOCs detected", "{}"

        # Create highlighted text
        highlighted = create_highlighted_text(text, iocs)

        # Create table data
        table_data = create_ioc_table(iocs)

        # Create JSON output
        json_output = create_json_output(iocs)

        return highlighted, table_data, json_output

    except Exception as e:
        logger.error(f"Error during extraction: {e}")
        return f"Error: {str(e)}", "Error during extraction", "{}"


def create_highlighted_text(text: str, iocs: List) -> str:
    """Create HTML with highlighted IOCs."""
    # Sort by position (reverse) to replace from end
    sorted_iocs = sorted(iocs, key=lambda x: x.start, reverse=True)

    result = text
    for ioc in sorted_iocs:
        color = ENTITY_COLORS.get(ioc.entity_type, "#888888")
        # Create highlighted span
        highlighted = (
            f'<mark style="background-color: {color}; padding: 2px 4px; '
            f'border-radius: 3px; color: #000;" '
            f'title="{ioc.entity_type} ({ioc.confidence:.2%})">'
            f"{ioc.value}</mark>"
        )
        result = result[: ioc.start] + highlighted + result[ioc.end :]

    return f"<div style='line-height: 1.8; font-size: 14px;'>{result}</div>"


def create_ioc_table(iocs: List) -> str:
    """Create markdown table of IOCs."""
    if not iocs:
        return "No IOCs detected"

    lines = ["| Type | Value | Confidence | Valid |", "|------|-------|------------|-------|"]

    for ioc in sorted(iocs, key=lambda x: (-x.confidence, x.entity_type)):
        valid_icon = "✅" if ioc.validated else "⚠️"
        lines.append(
            f"| {ioc.entity_type} | `{ioc.value}` | {ioc.confidence:.2%} | {valid_icon} |"
        )

    return "\n".join(lines)


def create_json_output(iocs: List) -> str:
    """Create JSON output of IOCs."""
    import json

    output = {
        "total_iocs": len(iocs),
        "iocs": [ioc.to_dict() for ioc in iocs],
        "by_type": {},
    }

    for ioc in iocs:
        if ioc.entity_type not in output["by_type"]:
            output["by_type"][ioc.entity_type] = []
        output["by_type"][ioc.entity_type].append(ioc.value)

    return json.dumps(output, indent=2)


def create_demo_interface():
    """Create the Gradio demo interface."""

    # Example texts for users to try
    examples = [
        [
            "APT29 was observed using Cobalt Strike to establish persistence on compromised "
            "systems. The attackers exploited CVE-2021-44228 to gain initial access and "
            "connected to C2 servers at 185.220.101.1 and evil-domain.com. The malware "
            "Emotet was also deployed with hash d41d8cd98f00b204e9800998ecf8427e."
        ],
        [
            "Security researchers identified a new campaign by Lazarus Group targeting "
            "financial institutions. The attack leveraged spearphishing emails from "
            "attacker@malicious.com containing invoice.xlsm which downloaded TrickBot "
            "from https://cdn.malicious.io/stage2.ps1."
        ],
        [
            "Incident response revealed the threat actor used Mimikatz for credential "
            "harvesting and established persistence via "
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run. Network traffic to "
            "91.219.28.45 was identified as Ryuk ransomware C2. File payload.exe with "
            "SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
            "was recovered."
        ],
    ]

    # Entity type options
    entity_types = list(ENTITY_COLORS.keys())

    with gr.Blocks(
        title="ThreatExtract-IOC-NER",
        theme=gr.themes.Soft(),
        css="""
        .container { max-width: 1200px; margin: auto; }
        .header { text-align: center; margin-bottom: 20px; }
        .footer { text-align: center; margin-top: 20px; color: #666; }
        """,
    ) as demo:

        gr.Markdown(
            """
            # 🔍 ThreatExtract-IOC-NER

            **Extract Indicators of Compromise (IOCs) from Threat Intelligence Text**

            This demo uses a fine-tuned transformer model to identify and extract
            cybersecurity IOCs including IP addresses, domains, file hashes, malware names,
            threat actors, CVEs, and more.

            ---
            """
        )

        with gr.Row():
            with gr.Column(scale=2):
                input_text = gr.Textbox(
                    label="📝 Input Text",
                    placeholder="Paste threat intelligence report, incident summary, or security advisory...",
                    lines=8,
                    max_lines=20,
                )

                with gr.Row():
                    confidence_slider = gr.Slider(
                        minimum=0.1,
                        maximum=1.0,
                        value=0.5,
                        step=0.05,
                        label="🎯 Minimum Confidence",
                    )
                    validate_checkbox = gr.Checkbox(
                        value=True,
                        label="✅ Validate IOCs",
                    )

                entity_filter = gr.CheckboxGroup(
                    choices=entity_types,
                    value=entity_types,
                    label="🏷️ Entity Types to Extract",
                )

                with gr.Row():
                    extract_btn = gr.Button("🔎 Extract IOCs", variant="primary", size="lg")
                    clear_btn = gr.Button("🗑️ Clear", variant="secondary")

            with gr.Column(scale=3):
                with gr.Tabs():
                    with gr.TabItem("📋 Highlighted Text"):
                        highlighted_output = gr.HTML(
                            label="Extracted IOCs",
                        )

                    with gr.TabItem("📊 IOC Table"):
                        table_output = gr.Markdown(
                            label="IOC Details",
                        )

                    with gr.TabItem("📄 JSON Output"):
                        json_output = gr.Code(
                            label="JSON Format",
                            language="json",
                        )

        # Legend
        gr.Markdown("### 🎨 Entity Type Legend")
        legend_html = "<div style='display: flex; flex-wrap: wrap; gap: 10px;'>"
        for entity_type, color in ENTITY_COLORS.items():
            legend_html += (
                f"<span style='background-color: {color}; padding: 4px 8px; "
                f"border-radius: 4px; color: #000;'>{entity_type}</span>"
            )
        legend_html += "</div>"
        gr.HTML(legend_html)

        # Examples
        gr.Markdown("### 💡 Try These Examples")
        gr.Examples(
            examples=examples,
            inputs=input_text,
        )

        # Event handlers
        extract_btn.click(
            fn=extract_iocs,
            inputs=[input_text, confidence_slider, validate_checkbox, entity_filter],
            outputs=[highlighted_output, table_output, json_output],
        )

        clear_btn.click(
            fn=lambda: ("", "", "{}"),
            outputs=[highlighted_output, table_output, json_output],
        )

        gr.Markdown(
            """
            ---

            ### ℹ️ About

            **ThreatExtract-IOC-NER** is a Named Entity Recognition model specifically
            fine-tuned for extracting Indicators of Compromise from cybersecurity text.

            **Supported IOC Types:**
            - Network: IPv4, IPv6, Domain, URL, Email
            - File Hashes: MD5, SHA1, SHA256
            - Vulnerabilities: CVE IDs
            - Threat Intel: Malware, Threat Actors, Campaigns, Tools, Techniques
            - System: Registry Keys, File Paths, File Names

            **Model:** Fine-tuned on threat intelligence data using transformer architecture.

            ---
            Made with ❤️ for the cybersecurity community
            """
        )

    return demo


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run ThreatExtract-IOC-NER Gradio Demo"
    )
    parser.add_argument(
        "--model_path",
        type=str,
        default=None,
        help="Path to trained model (HuggingFace ID or local path)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=7860,
        help="Port to run the demo on",
    )
    parser.add_argument(
        "--share",
        action="store_true",
        help="Create a public shareable link",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Run in debug mode",
    )

    args = parser.parse_args()

    # Try to load model
    if args.model_path:
        success = load_model(args.model_path)
        if not success:
            logger.warning(
                "Could not load specified model. Demo will show error messages."
            )
    else:
        # Try default paths
        default_paths = [
            "./output/threatextract-ioc-ner/final_model",
            "./output/threatextract-ioc-ner",
            "ftrout/ThreatExtract-IOC-NER",
        ]
        for path in default_paths:
            if Path(path).exists() or not path.startswith("."):
                success = load_model(path)
                if success:
                    break
        else:
            logger.warning(
                "No model found. Please train a model or specify --model_path"
            )

    # Create and launch demo
    demo = create_demo_interface()
    demo.launch(
        server_port=args.port,
        share=args.share,
        debug=args.debug,
    )


if __name__ == "__main__":
    main()
