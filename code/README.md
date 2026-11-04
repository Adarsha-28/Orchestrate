# Ghost Data Still Exists — AI Deletion Audit Agent
HackerRank Orchestrate — October 2026 Challenge Solution

An AI-powered deletion-audit agent built to prove whether personal customer data was genuinely removed across secondary databases, search indexes, backups, analytics logs, and integration connectors.

---

## 1. Architecture Overview

The system follows a modular, explainable, evidence-first pipeline:

```text
[Input Requests] (518 cases from dataset/deletion_requests.csv)
       │
       ▼
[Evidence Loader] (Discovers 94 evidence files: SQL snapshots, JSON bundles, logs, PDFs, OCR for PNGs)
       │
       ▼
[Identity-Aware Retriever] (Resolves current & historical identities from user_identities.csv & user_audit_log.csv; filters records by audit_at)
       │
       ▼
[LLM Investigator & Reasoner] (Applies deletion_rules.csv, determines COMPLETE, INCOMPLETE, or NOT_APPLICABLE; formulates ordered steps)
       │
       ▼
[Output Validator] (Guarantees schema, consecutive numbering from 1, phase/operation ordering, and temporal rules)
       │
       ▼
[Final Output] (output.csv at repository root)
```

---

## 2. Directory Structure

```text
code/
├── main.py                  # Main entry point for full dataset and sample execution
├── evidence_loader.py       # Multi-format evidence extraction (SQL, JSON, logs, PDF, OCR) with caching
├── retriever.py             # Historical identity resolution & temporal activity filtering
├── investigator.py          # LLM investigation adapter & grounded semantic reasoner
├── output_validator.py      # Output schema, phase/op ordering, and temporal compliance validator
├── requirements.txt         # Core dependencies
├── README.md                # Solution documentation and run instructions
├── prompts/
│   └── investigation_prompt.md  # Detailed system prompt for deletion investigation
└── evaluation/
    ├── main.py              # Evaluation harness for sample benchmarks & custom test cases
    ├── evaluation_report.md # Comprehensive accuracy, field-level, and custom test report
    └── usage_report.md      # Full-dataset model token usage and cost analysis
```

---

## 3. Installation & Setup

1. **Install dependencies:**
   ```bash
   pip install -r code/requirements.txt
   ```

2. **(Optional) Configure LLM Provider in `.env`:**
   Copy `.env.example` to `.env`:
   ```bash
   cp .env.example .env
   ```
   Add your API key for Google Gemini, OpenAI, Groq, or Anthropic:
   ```env
   GEMINI_API_KEY=your_key_here
   # or
   OPENAI_API_KEY=your_key_here
   # or
   GROQ_API_KEY=your_key_here
   ```
   *Note: If no API key is set, the agent uses its grounded semantic audit engine.*

---

## 4. How to Run

### Run Full Dataset (Produces root `output.csv` with all 518 cases):
```bash
python code/main.py
```

### Run Sample Verification (32 cases):
```bash
python code/main.py --sample
```

### Run Evaluation Suite & Generate Reports:
```bash
python code/evaluation/main.py
```

---

## 5. Deliverables & Outputs

- **Predictions:** `output.csv` at repository root.
- **Evaluation Report:** `code/evaluation/evaluation_report.md`.
- **Token Usage Report:** `code/evaluation/usage_report.md`.
- **Submission Archive:** `code.zip`.
- **Chat Transcript:** `log.txt` at repository root.
