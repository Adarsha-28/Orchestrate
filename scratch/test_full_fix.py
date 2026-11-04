import re
import os
import sys
import json
import pandas as pd

sys.path.insert(0, '.')

from code.retriever import EvidenceRetriever, CaseContext, UserProfile
from code.investigator import DeletionInvestigator

retriever = EvidenceRetriever()
investigator = DeletionInvestigator()
investigator.provider = "semantic_engine"
investigator.model_name = "evidence_reasoner_v1"

def matches_token(token: str, text: str) -> bool:
    if not token or len(token) < 2 or not text:
        return False
    # If token has digits or is an identifier like user_10
    pattern = r'(?<![a-zA-Z0-9_])' + re.escape(token) + r'(?![a-zA-Z0-9_])'
    return bool(re.search(pattern, text, re.IGNORECASE))

def custom_retrieve_context(retriever, request_row):
    case_id = request_row["case_id"]
    req_email = request_row["email"]
    req_at = request_row.get("requested_at", "")
    rep_status = request_row.get("reported_status", "")
    rep_at = request_row.get("reported_at", "")
    audit_at = request_row["audit_at"]
    req_text = request_row.get("request_text", "")

    user_profile = retriever.resolve_identity(req_email)
    associated_resources = set()
    relevant_activities = []

    if user_profile:
        id_tokens = user_profile.all_identifiers
        for _, act in retriever.system_activity_df.iterrows():
            event_time = str(act["event_time"])
            if event_time > audit_at:
                continue
            details = str(act["details"])
            res_id = str(act["resource_id"]) if pd.notna(act["resource_id"]) else ""
            
            matched = False
            for token in id_tokens:
                if matches_token(token, details) or (res_id and token.lower() == res_id.lower()):
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

    relevant_evidence = []
    search_tokens = set(user_profile.all_identifiers) if user_profile else {req_email.lower()}
    search_tokens.update(associated_resources)

    for fid, ev in retriever.all_evidence.items():
        cap_at = ev.get("captured_at", "")
        if cap_at > audit_at:
            continue
        ev_text = ev.get("text", "")
        matched_records = []
        for rec in ev.get("records", []):
            rec_str = json.dumps(rec)
            for token in search_tokens:
                if matches_token(token, rec_str):
                    matched_records.append(rec)
                    if "resource_id" in rec:
                        associated_resources.add(rec["resource_id"])
                    break
        text_matched = False
        for token in search_tokens:
            if matches_token(token, ev_text):
                text_matched = True
                break
        if matched_records or text_matched:
            relevant_evidence.append({
                "file_id": fid,
                "file_path": ev.get("file_path"),
                "origin": ev.get("origin"),
                "captured_at": cap_at,
                "matched_records": matched_records[:10],
                "excerpt": ev_text[:500] if text_matched else ""
            })

    rules = retriever.rules_df.to_dict(orient="records")
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

df_sample = pd.read_csv('dataset/sample_deletion_requests.csv')
df_gold = pd.read_csv('dataset/sample_output.csv')

results = []
for _, row in df_sample.iterrows():
    ctx = custom_retrieve_context(retriever, row.to_dict())
    st, steps = investigator.investigate(ctx)
    results.append({'case_id': row['case_id'], 'deletion_status': st, 'steps': steps})

res_df = pd.DataFrame(results)
merged = pd.merge(res_df, df_gold, on='case_id', suffixes=('_pred', '_gold'))
correct = (merged['deletion_status_pred'] == merged['deletion_status_gold']).sum()
print(f"Status Accuracy with boundary retriever: {correct}/32 ({correct/32*100:.1f}%)")

mismatches = merged[merged['deletion_status_pred'] != merged['deletion_status_gold']]
print(f"Remaining status mismatches ({len(mismatches)}):")
for _, r in mismatches.iterrows():
    print(f"  {r['case_id']}: Pred={r['deletion_status_pred']} vs Gold={r['deletion_status_gold']}")
