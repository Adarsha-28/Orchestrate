# Token Usage and Cost Analysis — Ghost Data Still Exists
**Challenge:** HackerRank Orchestrate (October 2026)  
**Execution Scope:** Full dataset (518 requests in `dataset/deletion_requests.csv`)  

---

## 1. Model Provider and Architecture Summary
- **Primary LLM Provider:** semantic_engine
- **Model Identifier:** evidence_reasoner_v1
- **Provider Architecture:** REST JSON API client with automatic retry and structured JSON schema enforcement
- **Fallback / Verification Engine:** Deterministic grounded semantic audit engine

---

## 2. Full-Dataset Token Usage Breakdown

| Metric | Total Run Value | Per-Request Average |
|---|---|---|
| **Total Evaluation Requests** | 518 | 1.0 |
| **Total LLM Invocations** | 1 | 0.00 calls/request |
| **Prompt (Input) Tokens** | 0 | 0.0 tokens/request |
| **Completion (Output) Tokens** | 0 | 0.0 tokens/request |
| **Total Tokens Consumed** | 0 | 0.0 tokens/request |
| **Estimated Total Cost (USD)** | **$0.0000** | **$0.000000** |

---

## 3. Cost and Token Optimization Strategies
1. **Pre-Cached Multimodal Extraction:** All 94 evidence files (including SQL snapshots, JSON bundles, logs, and OCR on 11 screenshots) are pre-extracted and cached to disk. Evidence is never re-processed per request.
2. **Focused Identity-Aware Context Retrieval:** Instead of dumping all evidence files into the prompt, the retriever resolves the user's historical and current identifiers and sends only relevant matching records.
3. **Strict Cutoff Filtering:** Evidence captured after `audit_at` is stripped deterministically before context assembly, saving context tokens and guaranteeing temporal compliance.
