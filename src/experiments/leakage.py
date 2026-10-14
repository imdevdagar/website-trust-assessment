import sys, json
from pathlib import Path
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from src.utils.logging import get_logger
logger = get_logger(__name__)

LEAKAGE_REPORT = [
    {
        "feature": "FILENAME",
        "reason": "Dataset-specific file identifier. Directly encodes the source file name, "
                  "which is derived from the data collection process and is never available "
                  "in real deployment.",
        "available_in_deployment": False,
        "dataset_specific": True,
        "decision": "REMOVE",
    },
    {
        "feature": "URL",
        "reason": "Raw URL string. If fed to a classical ML model, it allows memorisation "
                  "of specific URLs seen during training. URL-derived numeric features are "
                  "used instead.",
        "available_in_deployment": True,
        "dataset_specific": False,
        "decision": "REMOVE (use extracted features instead)",
    },
    {
        "feature": "Domain",
        "reason": "Raw domain string. Not a numeric feature; domain-level leakage could occur "
                  "if the model memorises specific domain names. DomainLength and NoOfSubDomain "
                  "are used as numeric proxies.",
        "available_in_deployment": True,
        "dataset_specific": False,
        "decision": "REMOVE (use DomainLength, NoOfSubDomain instead)",
    },
    {
        "feature": "Title",
        "reason": "Raw page title string. Text field requiring NLP processing. "
                  "DomainTitleMatchScore uses it but that feature is flagged separately.",
        "available_in_deployment": "Only with webpage fetching",
        "dataset_specific": False,
        "decision": "REMOVE",
    },
    {
        "feature": "TLD",
        "reason": "Categorical string TLD. High cardinality; TLDLength is used as a numeric proxy.",
        "available_in_deployment": True,
        "dataset_specific": False,
        "decision": "REMOVE (use TLDLength instead)",
    },
    {
        "feature": "URLSimilarityIndex",
        "reason": "Computed by comparing the URL against a reference database of known URLs. "
                  "This reference set is not generally available at deployment time and may "
                  "encode information about the dataset collection process.",
        "available_in_deployment": "Only with external reference database",
        "dataset_specific": True,
        "decision": "FLAG (retained in full config; excluded in ablation config_c)",
    },
    {
        "feature": "TLDLegitimateProb",
        "reason": "Pre-computed probability of TLD legitimacy from a reference corpus. "
                  "Dataset-collection artifact that may not reflect the deployment distribution.",
        "available_in_deployment": "Only with reference corpus",
        "dataset_specific": True,
        "decision": "FLAG (retained in full config; excluded in ablation config_c)",
    },
    {
        "feature": "URLCharProb",
        "reason": "Pre-computed character-level probability based on a reference corpus. "
                  "Same concerns as TLDLegitimateProb.",
        "available_in_deployment": "Only with reference corpus",
        "dataset_specific": True,
        "decision": "FLAG (retained in full config; excluded in ablation config_c)",
    },
    {
        "feature": "DomainTitleMatchScore",
        "reason": "Requires fetching the live webpage to retrieve the page title, "
                  "then computing a similarity score against the domain. "
                  "Not available in passive URL-only mode.",
        "available_in_deployment": "Only with safe webpage fetching",
        "dataset_specific": False,
        "decision": "FLAG (retained in full config; not available in live URL mode)",
    },
    {
        "feature": "URLTitleMatchScore",
        "reason": "Requires fetching the live webpage title and comparing against the URL. "
                  "Same concerns as DomainTitleMatchScore.",
        "available_in_deployment": "Only with safe webpage fetching",
        "dataset_specific": False,
        "decision": "FLAG (retained in full config; not available in live URL mode)",
    },
]


def generate_leakage_report(out_path: str = "results/leakage_analysis.md") -> str:
    """Generate a structured leakage analysis Markdown report."""
    lines = [
        "# Data Leakage Analysis",
        "",
        "This report documents every feature inspected for potential data leakage.",
        "Features are classified as REMOVE (hard leakage) or FLAG (dataset-specific / ",
        "conditional availability).",
        "",
        "## Summary Table",
        "",
        "| Feature | Decision | Reason |",
        "|---------|----------|--------|",
    ]
    for entry in LEAKAGE_REPORT:
        lines.append(
            f"| {entry['feature']} | {entry['decision']} | "
            f"{entry['reason'][:80]}... |"
        )

    lines += ["", "## Detailed Analysis", ""]
    for entry in LEAKAGE_REPORT:
        lines += [
            f"### {entry['feature']}",
            f"- **Decision**: {entry['decision']}",
            f"- **Reason**: {entry['reason']}",
            f"- **Available in deployment**: {entry['available_in_deployment']}",
            f"- **Dataset-specific**: {entry['dataset_specific']}",
            "",
        ]

    report = "\n".join(lines)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    logger.info(f"Leakage report saved: {out_path}")
    return report


def get_remove_columns() -> list:
    return [e["feature"] for e in LEAKAGE_REPORT if "REMOVE" in e["decision"] and "FLAG" not in e["decision"]]
