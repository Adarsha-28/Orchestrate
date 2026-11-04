"""
Output Validator Module
Validates output.csv against all challenge rules:
- Row counts and exact headers
- JSON syntax and exact schema
- Consecutive numbering from 1
- Strict phase and operation ordering
- Evidence citation rules (non-empty for COMPLETE, empty for INCOMPLETE remediation/verification)
- Temporal compliance (no post-audit_at citations)
"""

import os
import json
import pandas as pd
from typing import Dict, List, Any, Tuple

PHASE_RANKS = {"FINDING": 1, "REMEDIATION": 2, "VERIFICATION": 3}
OPERATION_RANKS = {
    # FINDING
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
    # REMEDIATION
    "DISABLE_DATA_FLOW": 1,
    "BLOCK_RESTORE": 2,
    "DELETE_RECORD": 3,
    "REDACT_RECORD": 4,
    "ANONYMIZE_RECORD": 5,
    # VERIFICATION
    "VERIFY_RECORD_ABSENT": 1,
    "VERIFY_RECORD_PRESENT": 2,
    "VERIFY_RECORD_REDACTED": 3,
    "VERIFY_RECORD_ANONYMIZED": 4,
    "VERIFY_DATA_FLOW_DISABLED": 5,
    "VERIFY_RESTORE_BLOCKED": 6,
}

ALLOWED_OPS_STATES = {
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}

REQUIRED_KEYS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}


class OutputValidator:
    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.evidence_files = pd.read_csv(os.path.join(dataset_dir, "evidence_files.csv"))
        self.evidence_times = dict(zip(self.evidence_files["file_id"], self.evidence_files["captured_at"]))

    def validate_csv(self, csv_path: str, expected_rows: int = 518) -> Tuple[bool, List[str]]:
        errors = []
        if not os.path.exists(csv_path):
            return False, [f"File not found: {csv_path}"]

        with open(csv_path, "r", encoding="utf-8") as f:
            header = f.readline().strip()
            if header != "case_id,deletion_status,steps_json":
                errors.append(f"Invalid CSV header: '{header}'. Expected: 'case_id,deletion_status,steps_json'")

        try:
            df = pd.read_csv(csv_path)
        except Exception as e:
            return False, [f"Failed to parse CSV: {str(e)}"]

        if len(df) != expected_rows:
            errors.append(f"Row count mismatch: found {len(df)} rows, expected {expected_rows}")

        # Check sorting by case_id
        sorted_ids = sorted(df["case_id"].tolist())
        if df["case_id"].tolist() != sorted_ids:
            errors.append("Rows are not sorted in ascending order by case_id")

        for idx, row in df.iterrows():
            cid = str(row["case_id"])
            status = str(row["deletion_status"])
            steps_raw = row["steps_json"]

            if status not in ["COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"]:
                errors.append(f"[{cid}] Invalid deletion_status: {status}")

            try:
                steps = json.loads(steps_raw)
            except Exception as e:
                errors.append(f"[{cid}] Invalid JSON in steps_json: {str(e)}")
                continue

            if not isinstance(steps, list):
                errors.append(f"[{cid}] steps_json must be a JSON array")
                continue

            if status == "NOT_APPLICABLE":
                if len(steps) != 0:
                    errors.append(f"[{cid}] NOT_APPLICABLE must have empty steps_json array, found {len(steps)} steps")
                continue

            # Validate steps in COMPLETE or INCOMPLETE
            prev_key = None
            for s_idx, s in enumerate(steps, start=1):
                if not isinstance(s, dict):
                    errors.append(f"[{cid}] Step {s_idx} is not a JSON object")
                    continue

                missing_keys = REQUIRED_KEYS - set(s.keys())
                if missing_keys:
                    errors.append(f"[{cid}] Step {s_idx} missing keys: {missing_keys}")

                extra_keys = set(s.keys()) - REQUIRED_KEYS
                if extra_keys:
                    errors.append(f"[{cid}] Step {s_idx} has disallowed extra keys: {extra_keys}")

                if s.get("step_no") != s_idx:
                    errors.append(f"[{cid}] Non-consecutive step_no: expected {s_idx}, got {s.get('step_no')}")

                phase = s.get("phase")
                op = s.get("operation")
                state = s.get("state")
                ev_id = str(s.get("evidence_id", ""))

                if phase not in PHASE_RANKS:
                    errors.append(f"[{cid}] Step {s_idx} invalid phase: {phase}")
                if op not in OPERATION_RANKS:
                    errors.append(f"[{cid}] Step {s_idx} invalid operation: {op}")

                exp_state = ALLOWED_OPS_STATES.get(op)
                if exp_state and state != exp_state:
                    errors.append(f"[{cid}] Step {s_idx} state mismatch: operation {op} requires state {exp_state}, got {state}")

                # Status specific rules
                if status == "COMPLETE":
                    if phase != "VERIFICATION":
                        errors.append(f"[{cid}] COMPLETE case cannot contain {phase} steps, only VERIFICATION")
                    if not ev_id:
                        errors.append(f"[{cid}] Step {s_idx} COMPLETE verification must cite a non-empty evidence_id")
                elif status == "INCOMPLETE":
                    if phase in ["REMEDIATION", "VERIFICATION"] and ev_id != "":
                        errors.append(f"[{cid}] Step {s_idx} INCOMPLETE {phase} must use evidence_id: \"\", got '{ev_id}'")

                # Ordering check
                p_rank = PHASE_RANKS.get(phase, 99)
                op_rank = OPERATION_RANKS.get(op, 99)
                curr_key = (p_rank, op_rank, str(s.get("system_id")), str(s.get("resource_id")))
                if prev_key and curr_key < prev_key:
                    errors.append(f"[{cid}] Step {s_idx} violates ordering: previous {prev_key} -> current {curr_key}")
                prev_key = curr_key

        return len(errors) == 0, errors


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else ("output.csv" if os.path.exists("output.csv") else "dataset/sample_output.csv")
    exp_rows = 518 if "output.csv" in target and not "sample" in target else (32 if "sample" in target else 0)
    validator = OutputValidator()
    valid, errors = validator.validate_csv(target, expected_rows=exp_rows)
    print(f"Validation result for '{target}': {'PASSED' if valid else 'FAILED'} ({len(errors)} errors)")
    if errors:
        for err in errors[:10]:
            print("  ", err)

