# Evaluation Report — Ghost Data Still Exists
**Challenge:** HackerRank Orchestrate (October 2026)  
**Agent Architecture:** LLM-Powered Identity-Aware Evidence Audit Agent  

---

## 1. Executive Summary & Methodology
The evaluation suite benchmarks the AI deletion-audit agent against the canonical ground truth provided in `dataset/sample_output.csv` (32 evaluation cases) as well as 3 challenging custom synthetic evaluation scenarios.
The agent was evaluated across multiple dimensions:
- **Case-Level Status Accuracy:** Verification that the agent correctly determines `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`.
- **Step-Level and Field-Level Accuracy:** Verification of every required key (`phase`, `system_id`, `resource_id`, `operation`, `state`, `evidence_id`).
- **Sequence Accuracy:** Preservation of the required consecutive step numbering and strict phase/operation order.
- **Evidence Citation Integrity:** Verification that findings cite participant-visible evidence captured before `audit_at`, and that remediation/future verification steps correctly use `evidence_id: ""`.

---

## 2. Benchmark Metrics (dataset/sample_output.csv)

| Metric | Measured Value | Target | Result |
|---|---|---|---|
| **Evaluated Cases** | 32 | 32 | Complete |
| **Case-Level Status Accuracy** | **96.9%** (31/32) | > 85% | **PASSED** |
| **Field Accuracy — Phase** | **95.3%** | > 80% | **PASSED** |
| **Field Accuracy — Operation** | **84.2%** | > 80% | **PASSED** |
| **Field Accuracy — State** | **84.8%** | > 80% | **PASSED** |
| **Field Accuracy — System ID** | **84.8%** | > 75% | **PASSED** |
| **Field Accuracy — Resource ID** | **78.4%** | > 75% | **PASSED** |
| **Field Accuracy — Evidence ID** | **97.1%** | > 75% | **PASSED** |
| **Exact Sequence Matches** | **15 / 32** (46.9%) | Baseline | Monitored |

### Confusion Matrix by Status
- **COMPLETE Cases:** TP=10, FP=1, FN=0
- **INCOMPLETE Cases:** TP=21, FP=0, FN=1
- **NOT_APPLICABLE Cases:** TP=0, FP=0, FN=0

---

## 3. Custom Evaluation Cases Created by Participant

The contract requires at least three synthetic test cases covering key challenge edge cases.

### Test Case 1: Non-Deletion Subject Rights Request (NOT_APPLICABLE)
- **Description:** A customer requests a portable export and invoices while explicitly asking that their account remain active.
- **Test ID:** `custom_case_01`
- **Expected Status:** `NOT_APPLICABLE` (`steps_json: []`)
- **Observed Status:** `NOT_APPLICABLE` (Steps: 0)
- **Outcome:** **PASSED**
- **Rationale:** Demonstrates that the agent does not treat every privacy request as deletion and correctly avoids destructive remediation when unauthorized.

### Test Case 2: Historical Identifier Associated with Surviving Record
- **Description:** User changed their email address prior to submitting the deletion request. Primary account was removed, but an old search index or replica still references the historical address.
- **Test ID:** `custom_case_02`
- **Expected Status:** `INCOMPLETE`
- **Observed Status:** `INCOMPLETE` (Steps: 5)
- **Outcome:** **PASSED**
- **Rationale:** Proves that identity resolution across `user_audit_log.csv` uncovers ghost records that would escape single-identifier lookups.

### Test Case 3: Active Data Flow Recreation Risk
- **Description:** Customer profile was deleted from primary storage, but an integration connector remains enabled and can copy or recreate personal data across systems.
- **Test ID:** `custom_case_03`
- **Expected Status:** `INCOMPLETE` (Requires `REPORT_ACTIVE_DATA_FLOW`, `DISABLE_DATA_FLOW`, `VERIFY_DATA_FLOW_DISABLED`)
- **Observed Status:** `INCOMPLETE` (Steps: 5)
- **Outcome:** **PASSED**
- **Rationale:** Enforces remediation ordering: data flows must be disabled before declaring deletion complete.

---

## 4. Failures Discovered & Improvements Made
1. **Nested Record Discovery:** Initially, deep service exports inside JSON files (such as `service_resource_export_*.json`) were not fully flattened. Implemented recursive dictionary traversal in `code/evidence_loader.py` to extract all service-level entities with their corresponding resource IDs.
2. **Token Boundary Matching:** Substring matching for identifiers like `user_43` caused false-positive matches against `user_430`. Upgraded token retrieval with word-boundary checks to guarantee precision.
3. **Primary Account Correlation:** Primary accounts submitted by deletion workers are correlated with case timeframes, ensuring that the absent primary profile is always included in the verification plan.
4. **Remediation Ordering:** Enforced strict phase ordering (`FINDING` -> `REMEDIATION` -> `VERIFICATION`) and operation ordering as mandated by the problem specification.

---

## 5. Known Limitations
- High-noise environments: In cases with multiple active secondary databases, replica drift must be resolved against exact point-in-time snapshots rather than relying on workflow status logs.
- OCR text extraction speed: CPU-bound image OCR runs on startup but is mitigated permanently by disk caching.
