"""
Evidence Retriever Module
Performs identity resolution across current and historical records.
Retrieves relevant system activity and evidence up to audit_at.
Filters out any evidence captured after audit_at.
"""

import os
import json
import pandas as pd
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field

import re

try:
    from code.evidence_loader import EvidenceLoader
except ImportError:
    from evidence_loader import EvidenceLoader


def token_matches_text(token: str, text: str) -> bool:
    if not token or len(token) < 2 or not text:
        return False
    if token.startswith(('user_', 'account_', 'backup_', 'data_flow_', 'analytics_', 'support_', 'search_', 'tombstone_', 'audit_record_')):
        return bool(re.search(r'(?<![a-zA-Z0-9_])' + re.escape(token) + r'(?![a-zA-Z0-9_])', text, re.IGNORECASE))
    if "@" in token:
        return bool(re.search(r'(?<![a-zA-Z0-9_.+-])' + re.escape(token) + r'(?![a-zA-Z0-9_.+-])', text, re.IGNORECASE))
    if len(token) >= 4:
        return bool(re.search(r'\b' + re.escape(token) + r'\b', text, re.IGNORECASE))
    return False


@dataclass
class UserProfile:
    user_id: str
    current_name: Optional[str] = None
    current_email: Optional[str] = None
    current_phone: Optional[str] = None
    current_email_hash: Optional[str] = None
    historical_names: Set[str] = field(default_factory=set)
    historical_emails: Set[str] = field(default_factory=set)
    historical_phones: Set[str] = field(default_factory=set)
    historical_hashes: Set[str] = field(default_factory=set)
    all_identifiers: Set[str] = field(default_factory=set)


@dataclass
class CaseContext:
    case_id: str
    request_email: str
    requested_at: str
    reported_status: str
    reported_at: str
    audit_at: str
    request_text: str
    user_profile: Optional[UserProfile]
    applicable_rules: List[Dict[str, str]]
    relevant_activities: List[Dict[str, Any]]
    relevant_evidence: List[Dict[str, Any]]
    associated_resources: Set[str]


class EvidenceRetriever:
    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.loader = EvidenceLoader(dataset_dir)
        self.all_evidence = self.loader.load_all_evidence()
        
        self.identities_df = pd.read_csv(os.path.join(dataset_dir, "user_identities.csv"))
        self.audit_log_df = pd.read_csv(os.path.join(dataset_dir, "user_audit_log.csv"))
        self.system_activity_df = pd.read_csv(os.path.join(dataset_dir, "system_activity.csv"))
        self.rules_df = pd.read_csv(os.path.join(dataset_dir, "deletion_rules.csv"))
        
        # Build identity indexes for fast lookup
        self._build_identity_indexes()

    def _build_identity_indexes(self):
        self.email_to_user_id = {}
        for _, row in self.identities_df.iterrows():
            uid = str(row["user_id"])
            em = str(row["email"]).lower().strip()
            self.email_to_user_id[em] = uid

        for _, row in self.audit_log_df.iterrows():
            uid = str(row["user_id"])
            field_name = str(row["field_name"])
            if field_name == "email":
                if pd.notna(row["old_value"]):
                    self.email_to_user_id[str(row["old_value"]).lower().strip()] = uid
                if pd.notna(row["new_value"]):
                    self.email_to_user_id[str(row["new_value"]).lower().strip()] = uid

    def resolve_identity(self, email: str) -> Optional[UserProfile]:
        clean_email = str(email).lower().strip()
        uid = self.email_to_user_id.get(clean_email)
        if not uid:
            return None

        # Get current identity
        user_rows = self.identities_df[self.identities_df["user_id"] == uid]
        current_name = None
        current_email = None
        current_phone = None
        current_hash = None
        
        if not user_rows.empty:
            ur = user_rows.iloc[0]
            current_name = str(ur["name"]) if pd.notna(ur["name"]) else None
            current_email = str(ur["email"]) if pd.notna(ur["email"]) else None
            current_phone = str(ur["phone"]) if pd.notna(ur["phone"]) else None
            current_hash = str(ur["email_hash"]) if pd.notna(ur["email_hash"]) else None

        # Get historical changes
        audit_rows = self.audit_log_df[self.audit_log_df["user_id"] == uid]
        historical_names = set()
        historical_emails = set()
        historical_phones = set()
        historical_hashes = set()

        for _, ar in audit_rows.iterrows():
            fn = ar["field_name"]
            for val in [ar["old_value"], ar["new_value"]]:
                if pd.notna(val):
                    val_str = str(val).strip()
                    if fn == "name":
                        historical_names.add(val_str)
                    elif fn == "email":
                        historical_emails.add(val_str.lower())
                    elif fn == "phone":
                        historical_phones.add(val_str)
                    elif fn == "email_hash":
                        historical_hashes.add(val_str.lower())

        import hashlib
        for em in list(historical_emails) + ([current_email] if current_email else []) + [clean_email]:
            try:
                h = hashlib.sha256(em.strip().lower().encode("utf-8")).hexdigest()
                historical_hashes.add(h)
            except Exception:
                pass

        all_ids = {uid, clean_email}
        if current_name:
            all_ids.add(current_name)
        if current_email:
            all_ids.add(current_email.lower())
        if current_phone:
            all_ids.add(current_phone)
        if current_hash:
            all_ids.add(current_hash)
        
        all_ids.update(historical_names)
        all_ids.update(historical_emails)
        all_ids.update(historical_phones)
        all_ids.update(historical_hashes)

        return UserProfile(
            user_id=uid,
            current_name=current_name,
            current_email=current_email,
            current_phone=current_phone,
            current_email_hash=current_hash,
            historical_names=historical_names,
            historical_emails=historical_emails,
            historical_phones=historical_phones,
            historical_hashes=historical_hashes,
            all_identifiers=all_ids
        )

    def retrieve_context(self, request_row: Dict[str, Any]) -> CaseContext:
        case_id = request_row["case_id"]
        req_email = request_row["email"]
        req_at = request_row.get("requested_at", "")
        rep_status = request_row.get("reported_status", "")
        rep_at = request_row.get("reported_at", "")
        audit_at = request_row["audit_at"]
        req_text = request_row.get("request_text", "")

        user_profile = self.resolve_identity(req_email)
        associated_resources = set()
        relevant_activities = []

        if user_profile:
            # 1. Filter system activity <= audit_at
            # Look for mentions of user_id, emails, phones, names
            id_tokens = user_profile.all_identifiers
            # Fast filter on system activity
            for _, act in self.system_activity_df.iterrows():
                event_time = str(act["event_time"])
                if event_time > audit_at:
                    continue  # Strict cutoff
                
                details = str(act["details"])
                res_id = str(act["resource_id"]) if pd.notna(act["resource_id"]) else ""
                
                matched = False
                for token in id_tokens:
                    if len(token) >= 3:
                        if res_id and token.lower() == res_id.lower():
                            matched = True
                            break
                        if token.lower() in details.lower() and token_matches_text(token, details):
                            matched = True
                            break

                if matched:
                    if res_id:
                        associated_resources.add(res_id)
                    relevant_activities.append({
                        "activity_id": act["activity_id"],
                        "event_time": act["event_time"],
                        "event_type": act["event_type"],
                        "source_system": act["source_system"],
                        "target_system": act["target_system"],
                        "resource_id": res_id,
                        "reported_result": act["reported_result"],
                        "details": details
                    })

            # 1b. Deletion worker batch window correlation around reported_at
            if rep_at:
                try:
                    t_rep = pd.to_datetime(rep_at)
                    t_start = t_rep - pd.Timedelta(hours=2)
                    t_end = t_rep + pd.Timedelta(hours=2)
                    del_acts = self.system_activity_df[
                        (self.system_activity_df["source_system"] == "deletion_worker") &
                        (pd.to_datetime(self.system_activity_df["event_time"]) >= t_start) &
                        (pd.to_datetime(self.system_activity_df["event_time"]) <= t_end) &
                        (self.system_activity_df["event_time"] <= audit_at)
                    ]
                    t_lower = req_text.lower()
                    for _, act in del_acts.iterrows():
                        res_id = str(act["resource_id"]) if pd.notna(act["resource_id"]) else ""
                        ev_type = str(act["event_type"])
                        tgt = str(act["target_system"])
                        det = str(act["details"])
                        
                        # Only correlate if activity details actually match user identifier
                        matches_user = any(t.lower() in det.lower() and token_matches_text(t, det) for t in id_tokens)
                        include = matches_user
                            
                        if include and res_id and res_id not in associated_resources:
                            associated_resources.add(res_id)
                            relevant_activities.append({
                                "activity_id": act["activity_id"],
                                "event_time": act["event_time"],
                                "event_type": act["event_type"],
                                "source_system": act["source_system"],
                                "target_system": act["target_system"],
                                "resource_id": res_id,
                                "reported_result": act["reported_result"],
                                "details": str(act["details"])
                            })
                except Exception:
                    pass

        # 2. Filter evidence files
        relevant_evidence = []
        search_tokens = set(user_profile.all_identifiers) if user_profile else {req_email.lower()}
        search_tokens.update(associated_resources)

        for fid, ev in self.all_evidence.items():
            cap_at = ev.get("captured_at", "")
            can_cite = bool(cap_at and cap_at <= audit_at)
            
            ev_records = ev.get("records", [])
            if not can_cite:
                # If file was captured after audit_at, only keep records whose own timestamp <= audit_at
                ev_records = [r for r in ev_records if r.get("_time") and r["_time"] <= audit_at]
                if not ev_records:
                    continue
            
            ev_text = ev.get("text", "")
            matched_records = []
            
            # Check records
            for rec in ev_records:
                rec_str = json.dumps(rec)
                matched = False
                for f in ["user_reference", "user_id", "email", "customer_reference", "lookup_key", "match_key", "subject_ref", "resource_id", "owner_email", "requester_email", "correlation_key"]:
                    val = str(rec.get(f, "")).strip().lower()
                    if val and any(val == t.lower() for t in search_tokens):
                        matched = True
                        break
                if not matched:
                    for token in search_tokens:
                        if len(token) >= 3 and token.lower() in rec_str.lower():
                            if token_matches_text(token, rec_str):
                                matched = True
                                break
                if matched:
                    matched_records.append(rec)
                    if "resource_id" in rec and rec["resource_id"]:
                        associated_resources.add(str(rec["resource_id"]))

            # If text matches
            text_matched = False
            if can_cite:
                for token in search_tokens:
                    if len(token) >= 3 and token.lower() in ev_text.lower():
                        if token_matches_text(token, ev_text):
                            text_matched = True
                            break

            if matched_records or text_matched:
                relevant_evidence.append({
                    "file_id": fid,
                    "file_path": ev.get("file_path"),
                    "origin": ev.get("origin"),
                    "captured_at": cap_at,
                    "can_cite": can_cite,
                    "matched_records": matched_records[:10],
                    "excerpt": ev_text[:500] if text_matched else ""
                })

        rules = self.rules_df.to_dict(orient="records")

        return CaseContext(
            case_id=case_id,
            request_email=req_email,
            requested_at=req_at,
            reported_status=rep_status,
            reported_at=rep_at,
            audit_at=audit_at,
            request_text=req_text,
            user_profile=user_profile,
            applicable_rules=rules,
            relevant_activities=relevant_activities,
            relevant_evidence=relevant_evidence,
            associated_resources=associated_resources
        )
