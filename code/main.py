"""
Main Entry Point for Ghost Data Still Exists
HackerRank Orchestrate - October 2026
Builds and executes the AI-powered deletion-audit agent.
"""

import os
import sys
import argparse
import time
import json
import pandas as pd
from typing import List, Dict, Any

# Ensure local imports work cleanly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from code.retriever import EvidenceRetriever
from code.investigator import DeletionInvestigator
from code.output_validator import OutputValidator


def run_pipeline(
    input_path: str = "dataset/deletion_requests.csv",
    output_path: str = "output.csv",
    dataset_dir: str = "dataset",
    limit: int = 0,
    case_filter: str = "",
    quiet: bool = False
):
    start_time = time.time()
    if not quiet:
        print(f"=== HackerRank Orchestrate: Ghost Data Still Exists ===")
        print(f"Input: {input_path}")
        print(f"Output: {output_path}")

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input dataset not found: {input_path}")

    requests_df = pd.read_csv(input_path)
    total_cases = len(requests_df)

    if case_filter:
        if case_filter not in requests_df["case_id"].values:
            # Check alternative dataset (e.g., sample requests if evaluating case_01..32)
            alt_name = "sample_deletion_requests.csv" if "sample" not in input_path else "deletion_requests.csv"
            alt_path = os.path.join(dataset_dir, alt_name)
            if os.path.exists(alt_path):
                alt_df = pd.read_csv(alt_path)
                if case_filter in alt_df["case_id"].values:
                    requests_df = alt_df
                    input_path = alt_path
                    if not quiet:
                        print(f"Case '{case_filter}' resolved from {input_path}")
        requests_df = requests_df[requests_df["case_id"] == case_filter]
        if requests_df.empty:
            print(f"Case '{case_filter}' not found in {input_path}")
            return
    elif limit > 0:
        requests_df = requests_df.head(limit)

    if not quiet:
        print(f"Initializing EvidenceRetriever and DeletionInvestigator...")
    retriever = EvidenceRetriever(dataset_dir=dataset_dir)
    investigator = DeletionInvestigator()

    results = []
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}

    num_to_run = len(requests_df)
    for idx, (_, row) in enumerate(requests_df.iterrows(), start=1):
        case_id = row["case_id"]
        req_dict = row.to_dict()

        ctx = retriever.retrieve_context(req_dict)
        status, steps = investigator.investigate(ctx)

        status_counts[status] = status_counts.get(status, 0) + 1
        steps_json = json.dumps(steps, separators=(',', ':'))

        results.append({
            "case_id": case_id,
            "deletion_status": status,
            "steps_json": steps_json
        })

        if not quiet and (idx % 25 == 0 or idx == num_to_run or idx <= 5):
            print(f"[{idx}/{num_to_run}] {case_id}: status={status}, steps={len(steps)}")

    # Sort results by case_id
    results.sort(key=lambda x: x["case_id"])
    out_df = pd.DataFrame(results, columns=["case_id", "deletion_status", "steps_json"])

    # Ensure parent dir exists and do not overwrite root output.csv with a single debug case
    should_save = not (case_filter and output_path == "output.csv")
    if should_save:
        out_dir = os.path.dirname(output_path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        out_df.to_csv(output_path, index=False)
    else:
        if not quiet:
            print(f"(Single case inspection: skipped overwriting root {output_path})")

    elapsed = time.time() - start_time

    if not quiet:
        print("\n=== Execution Summary ===")
        print(f"Cases audited: {len(out_df)} in {elapsed:.2f}s ({elapsed/max(1, len(out_df)):.3f}s/case)")
        print(f"Status distribution: {status_counts}")
        print(f"LLM Provider: {investigator.usage.provider} (model: {investigator.usage.model_name})")
        print(f"LLM Calls: {investigator.usage.calls_count}, Total Tokens: {investigator.usage.total_tokens}")

        # Validate generated file if saved
        if should_save:
            validator = OutputValidator(dataset_dir=dataset_dir)
            valid, errors = validator.validate_csv(output_path, expected_rows=len(out_df))
            if valid:
                print(f"[SUCCESS] Output validation PASSED for all {len(out_df)} rows in {output_path}")
            else:
                print(f"[WARNING] Validation errors found ({len(errors)}):")
                for err in errors[:5]:
                    print(f"  - {err}")
        else:
            print(f"[Result] Status: {out_df.iloc[0]['deletion_status']}")
            print(f"[Result] Steps JSON: {out_df.iloc[0]['steps_json']}")

    return out_df, investigator.usage


def main():
    parser = argparse.ArgumentParser(description="HackerRank Orchestrate Deletion Audit Agent")
    parser.add_argument("--input", default="dataset/deletion_requests.csv", help="Path to input requests CSV")
    parser.add_argument("--output", default="output.csv", help="Path to output CSV (default: output.csv)")
    parser.add_argument("--dataset_dir", default="dataset", help="Dataset directory")
    parser.add_argument("--sample", action="store_true", help="Run on sample deletion requests")
    parser.add_argument("--limit", type=int, default=0, help="Limit number of requests to process")
    parser.add_argument("--case", default="", help="Process a single case ID")
    parser.add_argument("--quiet", action="store_true", help="Suppress progress logs")

    args = parser.parse_args()

    input_path = args.input
    output_path = args.output
    if args.sample:
        input_path = os.path.join(args.dataset_dir, "sample_deletion_requests.csv")
        if output_path == "output.csv":
            output_path = "sample_output_generated.csv"

    run_pipeline(
        input_path=input_path,
        output_path=output_path,
        dataset_dir=args.dataset_dir,
        limit=args.limit,
        case_filter=args.case,
        quiet=args.quiet
    )


if __name__ == "__main__":
    main()
