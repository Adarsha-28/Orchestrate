import pandas as pd
import json
import sys
sys.path.insert(0, '.')
from code.retriever import EvidenceRetriever

retriever = EvidenceRetriever()
df_sample = pd.read_csv('dataset/sample_deletion_requests.csv')
df_gold = pd.read_csv('dataset/sample_output.csv')

for cid in ['case_09', 'case_10']:
    row = df_sample[df_sample['case_id'] == cid].iloc[0].to_dict()
    gold_row = df_gold[df_gold['case_id'] == cid].iloc[0]
    ctx = retriever.retrieve_context(row)
    
    print("="*70)
    print(f"CASE: {cid} | Gold Status: {gold_row['deletion_status']}")
    print(f"Email: {row['email']} | Req at: {row['requested_at']} | Audit at: {row['audit_at']}")
    print(f"Reported status: {row['reported_status']} at {row['reported_at']}")
    print(f"Request text: {row['request_text']}")
    print(f"Resolved identifiers: {ctx.user_profile.all_identifiers if ctx.user_profile else 'None'}")
    
    # Gold steps
    g_steps = json.loads(gold_row['steps_json'])
    print(f"Gold Steps ({len(g_steps)}):")
    for s in g_steps:
        print(f"   {s['phase']} | {s['system_id']} | {s['resource_id']} | {s['operation']} | {s['state']} | {s['evidence_id']}")
        
    print(f"Relevant Activities ({len(ctx.relevant_activities)}):")
    for act in ctx.relevant_activities:
        print(f"   {act['event_time']} | {act['event_type']} | {act['source_system']} -> {act['target_system']} | res: {act['resource_id']} | result: {act['reported_result']}")
        print(f"      details: {act['details']}")
        
    print(f"Retrieved Evidence Files ({len(ctx.relevant_evidence)}):")
    for ev in ctx.relevant_evidence:
        print(f"   file_id: {ev['file_id']}, cap_at: {ev['captured_at']}, origin: {ev['origin']}, matches: {len(ev.get('matched_records', []))}")
        for r in ev.get('matched_records', []):
            print(f"      rec: {r}")
