import re
import os
import sys
import json
import pandas as pd

sys.path.insert(0, '.')

from code.retriever import EvidenceRetriever, CaseContext
from code.investigator import DeletionInvestigator

def token_in_text(token: str, text: str) -> bool:
    if not token or len(token) < 2:
        return False
    # Use word boundary
    pattern = r'(?<![a-zA-Z0-9_])' + re.escape(token) + r'(?![a-zA-Z0-9_])'
    return bool(re.search(pattern, text, re.IGNORECASE))

retriever = EvidenceRetriever()
investigator = DeletionInvestigator()
investigator.provider = "semantic_engine"
investigator.model_name = "evidence_reasoner_v1"

# Monkey-patch retrieve_context or test with improved retriever
orig_retrieve = retriever.retrieve_context

def improved_retrieve_context(request_row):
    ctx = orig_retrieve(request_row)
    
    # Filter matched evidence to only records that genuinely match the user's specific identifiers with word boundaries
    if not ctx.user_profile:
        return ctx
        
    u_tokens = set(ctx.user_profile.all_identifiers)
    clean_ev = []
    
    for ev in ctx.relevant_evidence:
        good_recs = []
        for rec in ev.get("matched_records", []):
            rec_str = json.dumps(rec)
            # Check if any user identifier matches with exact boundaries
            matched = False
            for t in u_tokens:
                if token_in_text(t, rec_str):
                    matched = True
                    break
            if matched:
                good_recs.append(rec)
                
        # Also check text
        ev_text = ev.get("excerpt", "")
        text_matched = False
        for t in u_tokens:
            if token_in_text(t, ev_text):
                text_matched = True
                break
                
        if good_recs or text_matched:
            ev_copy = dict(ev)
            ev_copy["matched_records"] = good_recs
            clean_ev.append(ev_copy)
            
    ctx.relevant_evidence = clean_ev
    return ctx

df_sample = pd.read_csv('dataset/sample_deletion_requests.csv')
df_gold = pd.read_csv('dataset/sample_output.csv')

results = []
for _, row in df_sample.iterrows():
    ctx = improved_retrieve_context(row.to_dict())
    st, steps = investigator.investigate(ctx)
    results.append({'case_id': row['case_id'], 'deletion_status': st, 'steps': steps})

res_df = pd.DataFrame(results)
merged = pd.merge(res_df, df_gold, on='case_id', suffixes=('_pred', '_gold'))
correct = (merged['deletion_status_pred'] == merged['deletion_status_gold']).sum()
print(f"Status Accuracy with boundary filtering: {correct}/32 ({correct/32*100:.1f}%)")

mismatches = merged[merged['deletion_status_pred'] != merged['deletion_status_gold']]
print("Remaining status mismatches:")
for _, r in mismatches.iterrows():
    print(f"  {r['case_id']}: Pred={r['deletion_status_pred']} vs Gold={r['deletion_status_gold']}")
