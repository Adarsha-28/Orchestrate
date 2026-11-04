"""
Evidence Loader Module
Discovers and extracts content from all evidence files in dataset/evidence/
Supports SQL, JSON, LOG, TXT, PDF, and PNG formats.
Implements disk caching for fast subsequent loads.
"""

import os
import json
import sqlite3
import re
from typing import Dict, List, Any, Optional

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

easyocr = None

CACHE_FILE = os.path.join(os.path.dirname(__file__), ".cache", "parsed_evidence.json")


class EvidenceLoader:
    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.manifest_path = os.path.join(dataset_dir, "evidence_files.csv")
        self.evidence_dir = os.path.join(dataset_dir, "evidence")
        self.files_meta = {}
        self.parsed_cache = {}
        self.ocr_reader = None
        self._load_manifest()

    def _load_manifest(self):
        import pandas as pd
        if not os.path.exists(self.manifest_path):
            return
        df = pd.read_csv(self.manifest_path)
        for _, row in df.iterrows():
            self.files_meta[row["file_id"]] = {
                "file_id": row["file_id"],
                "file_path": row["file_path"],
                "origin": row["origin"],
                "captured_at": row["captured_at"],
            }

    def _get_ocr_reader(self):
        global easyocr
        if self.ocr_reader is None:
            if easyocr is None:
                try:
                    import easyocr
                except ImportError:
                    pass
            if easyocr is not None:
                self.ocr_reader = easyocr.Reader(["en"], gpu=False)
        return self.ocr_reader

    def extract_file(self, file_id: str) -> Dict[str, Any]:
        """Extracts content and structured records from an evidence file."""
        if file_id in self.parsed_cache:
            return self.parsed_cache[file_id]

        meta = self.files_meta.get(file_id)
        if not meta:
            return {"file_id": file_id, "error": "Not found in manifest"}

        rel_path = meta["file_path"]
        abs_path = os.path.join(self.dataset_dir, rel_path)
        if not os.path.exists(abs_path):
            return {"file_id": file_id, "error": f"File not found: {abs_path}"}

        ext = os.path.splitext(abs_path)[1].lower()
        records = []
        raw_text = ""

        try:
            if ext == ".sql":
                records, raw_text = self._parse_sql(abs_path)
            elif ext == ".json":
                records, raw_text = self._parse_json(abs_path)
            elif ext in [".log", ".txt"]:
                records, raw_text = self._parse_log_or_txt(abs_path)
            elif ext == ".pdf":
                records, raw_text = self._parse_pdf(abs_path)
            elif ext == ".png":
                records, raw_text = self._parse_png(abs_path)
            else:
                raw_text = open(abs_path, "r", encoding="utf-8", errors="ignore").read()
        except Exception as e:
            return {
                "file_id": file_id,
                "error": str(e),
                "origin": meta["origin"],
                "captured_at": meta["captured_at"],
                "file_path": rel_path
            }

        parsed = {
            "file_id": file_id,
            "origin": meta["origin"],
            "captured_at": meta["captured_at"],
            "file_path": rel_path,
            "records": records,
            "text": raw_text
        }
        self.parsed_cache[file_id] = parsed
        return parsed

    def _parse_sql(self, abs_path: str):
        content = open(abs_path, "r", encoding="utf-8", errors="ignore").read()
        records = []
        # Run in in-memory SQLite to reliably read all table rows
        con = sqlite3.connect(":memory:")
        try:
            con.executescript(content)
            cur = con.cursor()
            cur.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [r[0] for r in cur.fetchall()]
            for tbl in tables:
                cur.execute(f"PRAGMA table_info('{tbl}');")
                cols = [c[1] for c in cur.fetchall()]
                cur.execute(f"SELECT * FROM '{tbl}';")
                for row in cur.fetchall():
                    rec = dict(zip(cols, row))
                    rec["_table"] = tbl
                    if "record_json" in rec and rec["record_json"]:
                        try:
                            rj = json.loads(rec["record_json"])
                            if isinstance(rj, dict):
                                for k, v in rj.items():
                                    if k not in rec or not rec[k]:
                                        rec[k] = v
                                if "document" in rj and isinstance(rj["document"], dict):
                                    for dk, dv in rj["document"].items():
                                        if dk not in rec or not rec[dk]:
                                            rec[dk] = dv
                        except Exception:
                            pass
                    records.append(rec)
        except Exception:
            # Fallback regex extraction for INSERT statements
            insert_pattern = re.compile(r"INSERT\s+INTO\s+[\"']?(\w+)[\"']?\s+VALUES\s*\((.*?)\);", re.IGNORECASE)
            for m in insert_pattern.finditer(content):
                tbl, val_str = m.group(1), m.group(2)
                records.append({"_table": tbl, "_raw": val_str})
        finally:
            con.close()
        return records, content

    def _parse_json(self, abs_path: str):
        content = open(abs_path, "r", encoding="utf-8", errors="ignore").read()
        data = json.loads(content)
        records = self._extract_nested_records(data)
        return records, content

    def _extract_nested_records(self, data, parent_key="", service_context=""):
        records = []
        if isinstance(data, list):
            for item in data:
                records.extend(self._extract_nested_records(item, parent_key, service_context))
        elif isinstance(data, dict):
            # Check if this dict represents a service section
            curr_service = service_context
            if any(srv in parent_key.lower() for srv in ["account", "security", "support", "analytics", "search", "backup", "export", "identity", "integration", "notification"]):
                curr_service = parent_key

            # If it looks like a resource record
            if any(k in data for k in ["resource_id", "user_id", "email", "customer_reference", "subject_reference", "archive_key", "connector_name", "object_key"]):
                rec = dict(data)
                if parent_key and "_section" not in rec:
                    rec["_section"] = parent_key
                if curr_service and "_service" not in rec:
                    rec["_service"] = curr_service
                records.append(rec)
            # Recurse into nested structures
            for k, v in data.items():
                if isinstance(v, (dict, list)):
                    records.extend(self._extract_nested_records(v, k, curr_service))
        return records

    def _parse_log_or_txt(self, abs_path: str):
        content = open(abs_path, "r", encoding="utf-8", errors="ignore").read()
        lines = content.splitlines()
        records = []
        kv_pattern = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
        trace_users = {}

        for line in lines:
            line_str = line.strip()
            if not line_str or line_str.startswith("#"):
                continue

            rec = None
            # Check if pipe-delimited record (e.g. handover snapshot)
            if line_str.count("|") >= 4:
                parts = [p.strip() for p in line_str.split("|")]
                if len(parts) >= 5:
                    rec = {
                        "timestamp": parts[0].lstrip("- "),
                        "system_id": parts[1],
                        "_service": parts[1],
                        "resource_id": parts[2],
                        "category": parts[3],
                        "status": parts[4],
                        "state": parts[4],
                        "_section": parts[3].lower(),
                    }
                    if len(parts) > 5:
                        ident = parts[5].strip()
                        rec["identifier"] = ident
                        if "@" in ident:
                            rec["email"] = ident
                        elif ident.startswith("user_"):
                            rec["user_id"] = ident
                            rec["customer_reference"] = ident
            else:
                # Check if line contains a JSON payload
                json_start = line_str.find("{")
                if json_start != -1:
                    try:
                        rec = json.loads(line_str[json_start:])
                    except Exception:
                        pass

                if not rec:
                    raw_kvs = kv_pattern.findall(line_str)
                    if raw_kvs:
                        rec = {k: (v1 if v1 != '' else v2) for k, v1, v2 in raw_kvs}
                    else:
                        rec = {"_line": line_str}

            rec["_line"] = line_str
            first_token = line_str.split()[0] if line_str.split() else ""
            if len(first_token) >= 19 and first_token.startswith("2026-"):
                rec["_time"] = first_token.strip('[](),')
            elif rec.get("timestamp"):
                rec["_time"] = str(rec["timestamp"]).strip('[](),')
            tid = rec.get("trace_id")
            user = (
                rec.get("subject_key")
                or rec.get("subject_ref")
                or rec.get("lookup_key")
                or rec.get("match_key")
                or rec.get("customer_reference")
                or rec.get("customer_email")
                or rec.get("customer_key")
                or rec.get("user_id")
                or rec.get("email")
                or rec.get("owner_email")
                or rec.get("correlation_key")
                or rec.get("subject_selector")
            )
            if tid and user:
                trace_users[tid] = user
            records.append(rec)

        # Propagate trace_users to all records sharing the trace_id
        for r in records:
            tid = r.get("trace_id")
            if tid in trace_users and "user_reference" not in r:
                r["user_reference"] = trace_users[tid]

        return records, content

    def _parse_pdf(self, abs_path: str):
        text = ""
        records = []
        if fitz is not None:
            doc = fitz.open(abs_path)
            for page in doc:
                text += page.get_text() + "\n"

        # Extract structured entities from PDF text
        res_matches = re.findall(r"\b(support_\w+|account_\w+|audit_record_\w+|data_flow_\w+|backup_\w+|tombstone_\w+|search_\w+)\b", text, re.IGNORECASE)
        user_matches = re.findall(r"\b(user_\w+)\b", text, re.IGNORECASE)
        email_matches = re.findall(r"[\w\.-]+@[\w\.-]+\.\w+", text)

        for res in set(res_matches):
            rec = {"resource_id": res.lower(), "_text": text}
            if user_matches:
                rec["user_id"] = user_matches[0].lower()
            if email_matches:
                rec["email"] = email_matches[0].lower()
            records.append(rec)

        if not records:
            records.append({"_text": text})

        return records, text

    def _parse_png(self, abs_path: str):
        text = ""
        reader = self._get_ocr_reader()
        if reader is not None:
            results = reader.readtext(abs_path, detail=0)
            text = " ".join(results)
        records = [{"_text": text}]
        return records, text

    def load_all_evidence(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Loads and caches all evidence files."""
        os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
        if not force_refresh and os.path.exists(CACHE_FILE):
            try:
                with open(CACHE_FILE, "r", encoding="utf-8") as f:
                    self.parsed_cache = json.load(f)
                return self.parsed_cache
            except Exception:
                pass

        print(f"Parsing all {len(self.files_meta)} evidence files (caching results)...")
        for fid in self.files_meta:
            self.extract_file(fid)

        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(self.parsed_cache, f)
        print(f"Evidence cached to {CACHE_FILE}")
        return self.parsed_cache


if __name__ == "__main__":
    loader = EvidenceLoader()
    all_ev = loader.load_all_evidence()
    print(f"Loaded {len(all_ev)} evidence files successfully.")
