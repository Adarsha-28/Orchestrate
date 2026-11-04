import re
import os
import sys
import json
import pandas as pd

sys.path.insert(0, '.')

from code.retriever import EvidenceRetriever, CaseContext
from code.investigator import DeletionInvestigator

retriever = EvidenceRetriever()
investigator = DeletionInvestigator()
investigator.provider = "semantic_engine"
investigator.model_name = "evidence_reasoner_v1"

def match_token_in_record(token: str, rec: dict) -> bool:
    if not token or len(token) < 2:
        return False
    # Check directly against record values
    for k, v in rec.items():
        if k.startswith('_'):
            continue
        v_str = str(v)
        if token.lower() == v_str.lower():
            return True
        # If token is an identifier like user_10 or account_010
        if token.startswith(('user_', 'account_', 'backup_', 'data_flow_', 'analytics_', 'support_', 'search_')):
            if re.search(r'(?<![a-zA-Z0-9_])' + re.escape(token) + r'(?![a-zA-Z0-9_])', v_str, re.IGNORECASE):
                return True
        elif len(token) >= 4 and token.lower() in v_str.lower():
            # e.g. email or name
            if re.search(r'(?<![a-zA-Z0-9_])' + re.escape(token) + r'(?![a-zA-Z0-9_])', v_str, re.IGNORECASE):
                return True
    return False

# Test with this refined matcher
orig_retrieve = retriever.retrieve_context

def refined_retrieve_context(request_row):
    ctx = orig_retrieve(request_row)
    if not ctx.user_profile:
        return ctx
        
    search_tokens = set(ctx.user_profile.all_identifiers)
    search_tokens.update(ctx.associated_resources)
    
    clean_ev = []
    for ev in ctx.relevant_evidence:
        good_recs = []
        for rec in ev.get("matched_records", []):
            matched = False
            for t in search_tokens:
                if match_token_in_record(t, rec):
                    matched = True
                    break
            if matched:
                good_recs.append(rec)
        if good_recs or ev.get("excerpt"):
            ev_copy = dict(ev)
            ev_copy["matched_records"] = good_recs
            clean_ev.append(ev_copy)
    ctx.relevant_evidence = clean_ev
    return ctx

df_sample = pd.read_csv('dataset/sample_deletion_requests.csv')
df_gold = pd.read_csv('dataset/sample_output.csv')

results = []
for _, row in df_sample.iterrows():
    ctx = refined_retrieve_context(row.to_dict())
    st, steps = investigator.investigate(ctx)
    results.append({'case_id': row['case_id'], 'deletion_status': st, 'steps': steps})

res_df = pd.DataFrame(results)
merged = pd.merge(res_df, df_gold, on='case_id', suffixes=('_pred', '_gold'))
correct = (merged['deletion_status_pred'] == merged['deletion_status_gold']).sum()
print(f"Status Accuracy: {correct}/32 ({correct/32*100:.1f}%)")

mismatches = merged[merged['deletion_status_pred'] != merged['deletion_status_gold']]
print(f"Remaining status mismatches ({len(mismatches)}):")
for _, r in mismatches.iterrows():
    print(f"  {r['case_id']}: Pred={r['deletion_status_pred']} vs Gold={r['deletion_status_gold']}")
