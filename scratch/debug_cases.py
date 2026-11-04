import json
import sys
sys.path.insert(0, '.')
from code.retriever import EvidenceRetriever
from code.investigator import DeletionInvestigator
import pandas as pd

df = pd.read_csv('dataset/sample_deletion_requests.csv')
gold_df = pd.read_csv('dataset/sample_output.csv')

retriever = EvidenceRetriever()
investigator = DeletionInvestigator()

for cid in ["case_17", "case_22", "case_23"]:
    req_row = df[df['case_id'] == cid].iloc[0].to_dict()
    gold_row = gold_df[gold_df['case_id'] == cid].iloc[0]
    
    print("="*60)
    print(f"DEBUGGING {cid}:")
    print("Request email:", req_row["email"])
    print("Reported at:", req_row.get("reported_at"))
    print("Audit at:", req_row["audit_at"])
    print("Request text:", req_row["request_text"])
    
    ctx = retriever.retrieve_context(req_row)
    print("Profile:", ctx.user_profile)
    print("Associated resources:", ctx.associated_resources)
    print("Relevant activities count:", len(ctx.relevant_activities))
    for a in ctx.relevant_activities:
        print("  ACT:", a["activity_id"], a["event_time"], a["event_type"], a["target_system"], a["resource_id"], a["reported_result"])
    print("Relevant evidence count:", len(ctx.relevant_evidence))
    for ev in ctx.relevant_evidence:
        print("  EV:", ev["file_id"], ev.get("origin"), ev.get("captured_at"), "records:", len(ev.get("matched_records", [])))
        for r in ev.get("matched_records", [])[:3]:
            print("    rec:", r)
    
    status, steps = investigator.investigate(ctx)
    print("PRED STATUS:", status)
    print("GOLD STATUS:", gold_row["deletion_status"])
    print("GOLD STEPS:", gold_row["steps_json"])
