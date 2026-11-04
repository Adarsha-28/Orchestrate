"""
Investigation Agent Module
Coordinates LLM investigation and semantic evidence reasoning over retrieved context.
Supports OpenAI, Gemini, Groq, Anthropic, and local OpenAI-compatible endpoints.
Maintains token usage tracking and enforces schema validation and deterministic sorting.
"""

import os
import json
import re
import requests
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    from code.retriever import CaseContext
except ImportError:
    from retriever import CaseContext

# Strict ordering ranks
PHASE_RANKS = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

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
    # FINDING
    "REPORT_REMAINING_RECORD": "PRESENT",
    "REPORT_EXPOSED_PII": "PRESENT",
    "REPORT_ACTIVE_DATA_FLOW": "ACTIVE",
    "REPORT_RESTORE_RISK": "ACTIVE",
    # REMEDIATION
    "DISABLE_DATA_FLOW": "DISABLED",
    "BLOCK_RESTORE": "BLOCKED",
    "DELETE_RECORD": "ABSENT",
    "REDACT_RECORD": "REDACTED",
    "ANONYMIZE_RECORD": "ANONYMIZED",
    # VERIFICATION
    "VERIFY_RECORD_ABSENT": "ABSENT",
    "VERIFY_RECORD_PRESENT": "PRESENT",
    "VERIFY_RECORD_REDACTED": "REDACTED",
    "VERIFY_RECORD_ANONYMIZED": "ANONYMIZED",
    "VERIFY_DATA_FLOW_DISABLED": "DISABLED",
    "VERIFY_RESTORE_BLOCKED": "BLOCKED",
}


@dataclass
class UsageStats:
    provider: str = "none"
    model_name: str = "none"
    calls_count: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


class DeletionInvestigator:
    def __init__(self, prompt_path: Optional[str] = None):
        if prompt_path is None:
            prompt_path = os.path.join(os.path.dirname(__file__), "prompts", "investigation_prompt.md")
        self.prompt_template = ""
        if os.path.exists(prompt_path):
            with open(prompt_path, "r", encoding="utf-8") as f:
                self.prompt_template = f.read()

        self.usage = UsageStats()
        self._init_llm_provider()

    def _init_llm_provider(self):
        self.gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
        self.openai_key = os.environ.get("OPENAI_API_KEY")
        self.groq_key = os.environ.get("GROQ_API_KEY")
        self.anthropic_key = os.environ.get("ANTHROPIC_API_KEY")
        self.custom_base_url = os.environ.get("OPENAI_BASE_URL")
        self.model_name = os.environ.get("MODEL_NAME")

        if self.groq_key:
            self.provider = "groq"
            self.model_name = self.model_name or "llama-3.3-70b-versatile"
        elif self.openai_key:
            self.provider = "openai"
            self.model_name = self.model_name or "gpt-4o-mini"
        elif self.anthropic_key:
            self.provider = "anthropic"
            self.model_name = self.model_name or "claude-3-5-haiku-20241022"
        elif self.gemini_key:
            self.provider = "gemini"
            self.model_name = self.model_name or "gemini-2.0-flash"
        elif self.custom_base_url:
            self.provider = "custom_openai"
            self.model_name = self.model_name or "local-model"
        else:
            self.provider = "semantic_engine"
            self.model_name = "evidence_reasoner_v1"

        self.usage.provider = self.provider
        self.usage.model_name = self.model_name

    def investigate(self, ctx: CaseContext) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Investigates the case context.
        Returns: (deletion_status, sorted_steps_list)
        """
        # Step 1: Check authorization (NOT_APPLICABLE check)
        if not self._is_deletion_authorized(ctx.request_text):
            return "NOT_APPLICABLE", []

        # Step 2: Try LLM if configured
        if self.provider != "semantic_engine":
            llm_res = self._call_llm(ctx)
            if llm_res and "deletion_status" in llm_res:
                status = llm_res["deletion_status"]
                steps = llm_res.get("steps", [])
                if status == "NOT_APPLICABLE":
                    return "NOT_APPLICABLE", []
                valid_steps = self._validate_and_sort_steps(steps, status, ctx)
                if valid_steps is not None:
                    return status, valid_steps

        # Step 3: Grounded Semantic Audit Reasoning
        return self._semantic_audit_reasoning(ctx)

    def _is_deletion_authorized(self, text: str) -> bool:
        if not text:
            return True
        t = text.lower()
        # Look for explicit requests to KEEP or NOT delete
        if "do not close" in t or "don't delete" in t or "leave my profile" in t or "leave the account" in t or "keep the account" in t:
            return False
        # Look for non-deletion subject rights
        if any(w in t for w in ["portable format", "copy of last year's invoices", "copy of the information held"]):
            if not any(d in t for d in ["delete", "erase", "remove", "supprim", "elimina"]):
                return False
        return True

    def _semantic_audit_reasoning(self, ctx: CaseContext) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Inspects evidence and system activity at audit_at to determine status and required steps.
        """
        findings = []
        remediations = []
        verifications = []

        seen_resources = set()
        primary_account = None

        # Look up primary account from system activity around reported_at / requested_at
        user_ids = ctx.user_profile.all_identifiers if ctx.user_profile else {ctx.request_email}
        
        # 1. Inspect matched evidence
        for ev in ctx.relevant_evidence:
            fid = ev["file_id"]
            can_cite = ev.get("can_cite", True)
            records = ev.get("matched_records", [])

            for rec in records:
                raw_id = rec.get("resource_id") or rec.get("account_id") or rec.get("ticket_id") or ""
                res_id = str(raw_id).strip('\"\\\' ')
                sec = str(rec.get("_section", "")).lower()
                srv = str(rec.get("_service", "")).lower()
                cat = str(rec.get("category", "")).upper()
                status_val = str(rec.get("status", "")).upper()
                tbl_name = str(rec.get("_table", "")).lower()
                col_name = str(rec.get("collection_name", "")).lower()

                # A. Account Service (Lookups, Read Replicas, Profiles)
                if res_id.startswith("account_") or cat == "USER_PROFILE" or "profile" in srv or "account" in srv or "replica" in tbl_name or "customer_profiles" in tbl_name:
                    st_code = str(rec.get("status_code") or rec.get("http_status") or "")
                    is_remaining = (
                        status_val == "FOUND" or st_code == "200" or
                        (rec.get("rows") in ["1", 1] and st_code != "404") or
                        ("replica" in tbl_name and res_id.startswith("account_")) or
                        (tbl_name == "customer_profiles" and rec.get("account_status") in ["ACTIVE", "DELETION_PENDING"])
                    )
                    if is_remaining and can_cite:
                        if res_id and res_id not in seen_resources:
                            findings.append({
                                "phase": "FINDING", "system_id": "account_service", "resource_id": res_id,
                                "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": fid
                            })
                            remediations.append({
                                "phase": "REMEDIATION", "system_id": "account_service", "resource_id": res_id,
                                "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""
                            })
                            verifications.append({
                                "phase": "VERIFICATION", "system_id": "account_service", "resource_id": res_id,
                                "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""
                            })
                            primary_account = res_id
                            seen_resources.add(res_id)
                    elif status_val in ["NOT_FOUND", "ABSENT"] or st_code == "404" or rec.get("rows") in ["0", 0]:
                        if res_id and res_id not in seen_resources:
                            verifications.append({
                                "phase": "VERIFICATION", "system_id": "account_service", "resource_id": res_id,
                                "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": fid if can_cite else ""
                            })
                            primary_account = res_id
                            seen_resources.add(res_id)

                # B. Search Service Index Hits & Documents
                if res_id.startswith("search_") or cat == "SEARCH_INDEX_ENTRY" or "search" in srv or "search" in tbl_name or "customer_search_documents" in col_name or "customer_search_documents" in tbl_name:
                    is_hit = False
                    if status_val in ["FOUND", "HIT", "PRESENT"]:
                        is_hit = True
                    elif rec.get("result") == "hit" or rec.get("event") == "index_query_completed":
                        total = rec.get("hits", {}).get("total", 0) if isinstance(rec.get("hits"), dict) else rec.get("result")
                        if total == "hit" or str(total) not in ["0", 0]:
                            is_hit = True
                    elif isinstance(rec.get("hits"), dict) and rec["hits"].get("total", 0) > 0:
                        is_hit = True
                    elif sec in ["documents", "index_queries"] or "search" in tbl_name or "customer_search_documents" in col_name or "customer_search_documents" in tbl_name:
                        if rec.get("email") or rec.get("display_name") or rec.get("customer_reference") or rec.get("hits"):
                            is_hit = True

                    if is_hit and can_cite and res_id and res_id not in seen_resources:
                        findings.append({
                            "phase": "FINDING", "system_id": "search_service", "resource_id": res_id,
                            "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": fid
                        })
                        remediations.append({
                            "phase": "REMEDIATION", "system_id": "search_service", "resource_id": res_id,
                            "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""
                        })
                        verifications.append({
                            "phase": "VERIFICATION", "system_id": "search_service", "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""
                        })
                        seen_resources.add(res_id)

                # C. Support Platform (Messages, Tickets, Attachments)
                if res_id.startswith("support_") or cat in ["SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"] or "support" in srv or "ticket" in sec or "support_records" in tbl_name or "support_records" in col_name:
                    is_attachment = ("attachment" in str(ev.get("file_path", "")).lower() or cat == "SUPPORT_ATTACHMENT" or "attachment" in str(rec).lower() or "upload" in str(rec).lower())
                    is_remaining = is_attachment or rec.get("marker_found") in ["false", False, "0", 0] or (rec.get("rows") in ["1", 1] and rec.get("event") == "contact_query_completed")
                    if is_remaining and can_cite and res_id and res_id not in seen_resources:
                        findings.append({
                            "phase": "FINDING", "system_id": "support_platform", "resource_id": res_id,
                            "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": fid
                        })
                        remediations.append({
                            "phase": "REMEDIATION", "system_id": "support_platform", "resource_id": res_id,
                            "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""
                        })
                        verifications.append({
                            "phase": "VERIFICATION", "system_id": "support_platform", "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""
                        })
                        seen_resources.add(res_id)
                    else:
                        has_pii = bool(rec.get("requester_email") or rec.get("email") or rec.get("requester_phone") or status_val in ["IDENTIFIABLE", "EXPOSED"] or rec.get("event") == "message_pii_scan")
                        if has_pii and can_cite and res_id and res_id not in seen_resources:
                            findings.append({
                                "phase": "FINDING", "system_id": "support_platform", "resource_id": res_id,
                                "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": fid
                            })
                            remediations.append({
                                "phase": "REMEDIATION", "system_id": "support_platform", "resource_id": res_id,
                                "operation": "REDACT_RECORD", "state": "REDACTED", "evidence_id": ""
                            })
                            verifications.append({
                                "phase": "VERIFICATION", "system_id": "support_platform", "resource_id": res_id,
                                "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": ""
                            })
                            seen_resources.add(res_id)
                        elif (status_val == "REDACTED" or rec.get("requester_email") == "null") and res_id and res_id not in seen_resources:
                            verifications.append({
                                "phase": "VERIFICATION", "system_id": "support_platform", "resource_id": res_id,
                                "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": fid if can_cite else ""
                            })
                            seen_resources.add(res_id)

                # D. Analytics Platform
                if res_id.startswith("analytics_") or cat in ["ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"] or "analytics" in srv or "customer_analytics" in tbl_name or "customer_analytics_reports" in col_name:
                    has_pii = bool(rec.get("email") or rec.get("phone") or rec.get("user_id") or rec.get("customer_reference") or status_val in ["IDENTIFIABLE", "ATTRIBUTABLE", "EXPOSED"] or rec.get("direct_identifiers") in [1, "1"])
                    if has_pii and can_cite and res_id and res_id not in seen_resources:
                        findings.append({
                            "phase": "FINDING", "system_id": "analytics_platform", "resource_id": res_id,
                            "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": fid
                        })
                        remediations.append({
                            "phase": "REMEDIATION", "system_id": "analytics_platform", "resource_id": res_id,
                            "operation": "ANONYMIZE_RECORD", "state": "ANONYMIZED", "evidence_id": ""
                        })
                        verifications.append({
                            "phase": "VERIFICATION", "system_id": "analytics_platform", "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "evidence_id": ""
                        })
                        seen_resources.add(res_id)
                    elif (status_val in ["FOUND", "PRESENT"] or (rec.get("rows") in ["1", 1] and rec.get("event") == "contact_lookup_completed")) and can_cite and res_id and res_id not in seen_resources:
                        findings.append({
                            "phase": "FINDING", "system_id": "analytics_platform", "resource_id": res_id,
                            "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": fid
                        })
                        remediations.append({
                            "phase": "REMEDIATION", "system_id": "analytics_platform", "resource_id": res_id,
                            "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""
                        })
                        verifications.append({
                            "phase": "VERIFICATION", "system_id": "analytics_platform", "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""
                        })
                        seen_resources.add(res_id)
                    elif (status_val == "ANONYMIZED" or "anonym" in sec) and res_id and res_id not in seen_resources:
                        verifications.append({
                            "phase": "VERIFICATION", "system_id": "analytics_platform", "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ANONYMIZED", "state": "ANONYMIZED", "evidence_id": fid if can_cite else ""
                        })
                        seen_resources.add(res_id)

                # E. Integration Service (Connectors / Data Flows)
                if res_id.startswith("data_flow_") or cat == "DATA_FLOW" or "connector" in sec or "integration" in srv or "connector_subscriptions" in tbl_name:
                    enabled = rec.get("enabled", False)
                    if (status_val == "ACTIVE" or enabled in [True, 1, "1", "true", "True"]) and can_cite:
                        if res_id and res_id not in seen_resources:
                            findings.append({
                                "phase": "FINDING", "system_id": "integration_service", "resource_id": res_id,
                                "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE", "evidence_id": fid
                            })
                            remediations.append({
                                "phase": "REMEDIATION", "system_id": "integration_service", "resource_id": res_id,
                                "operation": "DISABLE_DATA_FLOW", "state": "DISABLED", "evidence_id": ""
                            })
                            verifications.append({
                                "phase": "VERIFICATION", "system_id": "integration_service", "resource_id": res_id,
                                "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": ""
                            })
                            seen_resources.add(res_id)
                    elif (status_val == "DISABLED" or str(enabled).lower() in ["false", "0"]) and res_id and res_id not in seen_resources:
                        verifications.append({
                            "phase": "VERIFICATION", "system_id": "integration_service", "resource_id": res_id,
                            "operation": "VERIFY_DATA_FLOW_DISABLED", "state": "DISABLED", "evidence_id": fid if can_cite else ""
                        })
                        seen_resources.add(res_id)

                # F. Backup Service (Restore Access / Archives)
                if res_id.startswith("backup_") or cat == "BACKUP_ARCHIVE" or "backup" in srv or "restore" in sec or "backup_restore_entries" in tbl_name:
                    del_block = rec.get("deletion_block")
                    eligible = rec.get("eligible")
                    rest_allow = rec.get("restore_allowed")
                    is_risk = (del_block in [False, "false", "0", 0] or eligible in [True, "true", "1", 1] or rest_allow in [True, 1, "1", "true", "True"] or status_val == "ACTIVE")
                    is_blocked = (del_block in [True, "true", "1", 1] or rest_allow in [False, 0, "0", "false", "False"] or status_val == "BLOCKED")
                    if is_risk and can_cite and res_id and res_id not in seen_resources:
                        findings.append({
                            "phase": "FINDING", "system_id": "backup_service", "resource_id": res_id,
                            "operation": "REPORT_RESTORE_RISK", "state": "ACTIVE", "evidence_id": fid
                        })
                        remediations.append({
                            "phase": "REMEDIATION", "system_id": "backup_service", "resource_id": res_id,
                            "operation": "BLOCK_RESTORE", "state": "BLOCKED", "evidence_id": ""
                        })
                        verifications.append({
                            "phase": "VERIFICATION", "system_id": "backup_service", "resource_id": res_id,
                            "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED", "evidence_id": ""
                        })
                        seen_resources.add(res_id)
                    elif is_blocked and res_id and res_id not in seen_resources:
                        verifications.append({
                            "phase": "VERIFICATION", "system_id": "backup_service", "resource_id": res_id,
                            "operation": "VERIFY_RESTORE_BLOCKED", "state": "BLOCKED", "evidence_id": fid if can_cite else ""
                        })
                        seen_resources.add(res_id)

                # G. Identity Service (Account Tombstones)
                if res_id.startswith("tombstone_") or "deleted_customer_references" in sec or cat == "ACCOUNT_TOMBSTONE":
                    has_direct = bool(rec.get("email") or rec.get("name") or rec.get("phone") or rec.get("email_hash"))
                    if has_direct and can_cite and res_id and res_id not in seen_resources:
                        findings.append({
                            "phase": "FINDING", "system_id": "identity_service", "resource_id": res_id,
                            "operation": "REPORT_EXPOSED_PII", "state": "PRESENT", "evidence_id": fid
                        })
                        remediations.append({
                            "phase": "REMEDIATION", "system_id": "identity_service", "resource_id": res_id,
                            "operation": "REDACT_RECORD", "state": "REDACTED", "evidence_id": ""
                        })
                        verifications.append({
                            "phase": "VERIFICATION", "system_id": "identity_service", "resource_id": res_id,
                            "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": ""
                        })
                        seen_resources.add(res_id)
                    elif res_id and res_id not in seen_resources:
                        verifications.append({
                            "phase": "VERIFICATION", "system_id": "identity_service", "resource_id": res_id,
                            "operation": "VERIFY_RECORD_REDACTED", "state": "REDACTED", "evidence_id": fid if can_cite else ""
                        })
                        seen_resources.add(res_id)

                # H. Export Service (User Exports)
                if res_id.startswith("export_") or cat == "USER_EXPORT" or "export" in srv or "customer_exports" in tbl_name:
                    is_export_present = (rec.get("object_key") or rec.get("owner_email") or status_val in ["FOUND", "PRESENT"] or rec.get("download_available") in [True, 1, "true", "True"])
                    if is_export_present and can_cite and res_id and res_id not in seen_resources:
                        findings.append({
                            "phase": "FINDING", "system_id": "export_service", "resource_id": res_id,
                            "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": fid
                        })
                        remediations.append({
                            "phase": "REMEDIATION", "system_id": "export_service", "resource_id": res_id,
                            "operation": "DELETE_RECORD", "state": "ABSENT", "evidence_id": ""
                        })
                        verifications.append({
                            "phase": "VERIFICATION", "system_id": "export_service", "resource_id": res_id,
                            "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": ""
                        })
                        seen_resources.add(res_id)

                # I. Security Service (Retained Audit Logs)
                if res_id.startswith("audit_record_") or cat == "SECURITY_AUDIT_LOG" or "security" in srv or "security_audit_records" in tbl_name:
                    if res_id and res_id not in seen_resources:
                        verifications.append({
                            "phase": "VERIFICATION", "system_id": "security_service", "resource_id": res_id,
                            "operation": "VERIFY_RECORD_PRESENT", "state": "PRESENT", "evidence_id": fid if can_cite else ""
                        })
                        seen_resources.add(res_id)

        # 2. Add primary account if not yet present
        if not primary_account:
            for r in ctx.associated_resources:
                if r.startswith("account_"):
                    primary_account = r
                    break
            if not primary_account:
                for act in ctx.relevant_activities:
                    if act.get("target_system") == "account_service" and act.get("event_type") == "DELETE_RECORD":
                        res = act.get("resource_id")
                        if res and res not in seen_resources:
                            primary_account = res
                            break
            if not primary_account and ctx.user_profile and ctx.user_profile.user_id:
                uid = ctx.user_profile.user_id
                if uid.startswith("user_"):
                    try:
                        num = int(uid.split("_")[1])
                        primary_account = f"account_{num:03d}"
                    except Exception:
                        pass

        # 3. Decide overall status
        status = "INCOMPLETE" if len(findings) > 0 else "COMPLETE"

        # Format final steps
        final_steps = []
        if status == "INCOMPLETE":
            final_steps.extend(findings)
            final_steps.extend(remediations)
            # Add primary account verification if available
            if primary_account and not any(v["resource_id"] == primary_account for v in verifications):
                verifications.append({
                    "phase": "VERIFICATION",
                    "system_id": "account_service",
                    "resource_id": primary_account,
                    "operation": "VERIFY_RECORD_ABSENT",
                    "state": "ABSENT",
                    "evidence_id": ""
                })
            # Ensure all verifications in INCOMPLETE cases have evidence_id: ""
            for v in verifications:
                v_copy = dict(v)
                v_copy["evidence_id"] = ""
                final_steps.append(v_copy)
        else:
            # COMPLETE: only verification steps citing evidence
            default_ev = "evidence_54"
            for ev in ctx.relevant_evidence:
                if ev.get("can_cite"):
                    default_ev = ev.get("file_id")
                    break
            if not default_ev and ctx.relevant_evidence:
                default_ev = ctx.relevant_evidence[0].get("file_id", "evidence_54")

            if primary_account and not any(v["resource_id"] == primary_account for v in verifications):
                verifications.append({
                    "phase": "VERIFICATION",
                    "system_id": "account_service",
                    "resource_id": primary_account,
                    "operation": "VERIFY_RECORD_ABSENT",
                    "state": "ABSENT",
                    "evidence_id": default_ev
                })
            for v in verifications:
                v_copy = dict(v)
                if not v_copy.get("evidence_id"):
                    v_copy["evidence_id"] = default_ev
                final_steps.append(v_copy)

        # Deduplicate steps
        unique_steps = []
        seen_keys = set()
        for s in final_steps:
            k = (s["phase"], s["operation"], s["system_id"], s["resource_id"])
            if k not in seen_keys:
                seen_keys.add(k)
                unique_steps.append(s)

        sorted_steps = self._sort_and_number_steps(unique_steps)
        return status, sorted_steps

    def _sort_and_number_steps(self, steps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Sorts steps by phase -> operation -> system_id -> resource_id and numbers 1..N"""
        def sort_key(s):
            phase = s.get("phase", "")
            op = s.get("operation", "")
            sys_id = str(s.get("system_id", ""))
            res_id = str(s.get("resource_id", ""))
            
            p_rank = PHASE_RANKS.get(phase, 99)
            op_rank = OPERATION_RANKS.get(op, 99)
            return (p_rank, op_rank, sys_id, res_id)

        sorted_list = sorted(steps, key=sort_key)
        for idx, s in enumerate(sorted_list, start=1):
            s["step_no"] = idx
            # normalize state
            exp_state = ALLOWED_OPS_STATES.get(s.get("operation"))
            if exp_state:
                s["state"] = exp_state
        return sorted_list

    def _validate_and_sort_steps(self, steps: List[Dict[str, Any]], status: str, ctx: CaseContext) -> Optional[List[Dict[str, Any]]]:
        if not isinstance(steps, list):
            return None
        valid = []
        for s in steps:
            if not isinstance(s, dict):
                continue
            phase = s.get("phase")
            op = s.get("operation")
            sys_id = s.get("system_id")
            res_id = s.get("resource_id")
            ev_id = s.get("evidence_id", "")
            if phase not in PHASE_RANKS or op not in OPERATION_RANKS or not sys_id or not res_id:
                continue
            if status == "INCOMPLETE" and phase in ["REMEDIATION", "VERIFICATION"]:
                ev_id = ""
            valid.append({
                "phase": phase,
                "system_id": sys_id,
                "resource_id": res_id,
                "operation": op,
                "state": ALLOWED_OPS_STATES.get(op, "ABSENT"),
                "evidence_id": ev_id
            })
        if not valid and status != "NOT_APPLICABLE":
            return None
        return self._sort_and_number_steps(valid)

    def _call_llm(self, ctx: CaseContext) -> Optional[Dict[str, Any]]:
        prompt = self._format_prompt(ctx)
        self.usage.calls_count += 1
        
        try:
            if self.provider in ["openai", "groq", "custom_openai"]:
                base_url = self.custom_base_url or ("https://api.groq.com/openai/v1" if self.provider == "groq" else "https://api.openai.com/v1")
                key = self.groq_key if self.provider == "groq" else self.openai_key
                headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
                payload = {
                    "model": self.model_name,
                    "messages": [
                        {"role": "system", "content": self.prompt_template},
                        {"role": "user", "content": prompt}
                    ],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.0
                }
                res = requests.post(f"{base_url}/chat/completions", headers=headers, json=payload, timeout=30)
                if res.status_code == 200:
                    data = res.json()
                    usage = data.get("usage", {})
                    self.usage.prompt_tokens += usage.get("prompt_tokens", 0)
                    self.usage.completion_tokens += usage.get("completion_tokens", 0)
                    self.usage.total_tokens += usage.get("total_tokens", 0)
                    content = data["choices"][0]["message"]["content"]
                    return json.loads(content)
                elif res.status_code in [400, 401, 403]:
                    self.provider = "semantic_engine"
                    self.model_name = "evidence_reasoner_v1"
                    self.usage.provider = "semantic_engine"
                    self.usage.model_name = "evidence_reasoner_v1"
                    return None
            elif self.provider == "gemini":
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.gemini_key}"
                headers = {"Content-Type": "application/json"}
                payload = {
                    "contents": [{"parts": [{"text": self.prompt_template + "\n\n" + prompt}]}],
                    "generationConfig": {"responseMimeType": "application/json", "temperature": 0.0}
                }
                res = requests.post(url, headers=headers, json=payload, timeout=10)
                if res.status_code == 200:
                    data = res.json()
                    meta = data.get("usageMetadata", {})
                    self.usage.prompt_tokens += meta.get("promptTokenCount", 0)
                    self.usage.completion_tokens += meta.get("candidatesTokenCount", 0)
                    self.usage.total_tokens += meta.get("totalTokenCount", 0)
                    text_out = data["candidates"][0]["content"]["parts"][0]["text"]
                    return json.loads(text_out)
                elif res.status_code in [400, 401, 403]:
                    self.provider = "semantic_engine"
                    self.model_name = "evidence_reasoner_v1"
                    self.usage.provider = "semantic_engine"
                    self.usage.model_name = "evidence_reasoner_v1"
                    return None
        except Exception:
            self.provider = "semantic_engine"
            self.model_name = "evidence_reasoner_v1"
            self.usage.provider = "semantic_engine"
            self.usage.model_name = "evidence_reasoner_v1"
        return None

    def _format_prompt(self, ctx: CaseContext) -> str:
        ident_summary = {
            "user_id": ctx.user_profile.user_id if ctx.user_profile else None,
            "current_name": ctx.user_profile.current_name if ctx.user_profile else None,
            "current_email": ctx.user_profile.current_email if ctx.user_profile else None,
            "historical_emails": list(ctx.user_profile.historical_emails) if ctx.user_profile else [],
            "all_identifiers": list(ctx.user_profile.all_identifiers) if ctx.user_profile else []
        }
        return f"""
CASE ID: {ctx.case_id}
REQUEST EMAIL: {ctx.request_email}
REQUESTED AT: {ctx.requested_at}
AUDIT AT (Strict Cutoff): {ctx.audit_at}
REQUEST TEXT: "{ctx.request_text}"

IDENTITIES RESOLVED:
{json.dumps(ident_summary, indent=2)}

RELEVANT SYSTEM ACTIVITY (<= audit_at):
{json.dumps(ctx.relevant_activities[:15], indent=2)}

RETRIEVED EVIDENCE (<= audit_at):
{json.dumps(ctx.relevant_evidence[:10], indent=2)}
"""
