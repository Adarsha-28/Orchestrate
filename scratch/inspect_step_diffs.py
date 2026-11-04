import json
import pandas as pd

pred_df = pd.read_csv("scratch/sample_run_output.csv")
gold_df = pd.read_csv("dataset/sample_output.csv")

cases_to_check = ["case_03", "case_04", "case_07", "case_09", "case_12", "case_17", "case_22", "case_23", "case_32"]

for cid in cases_to_check:
    p_row = pred_df[pred_df["case_id"] == cid].iloc[0]
    g_row = gold_df[gold_df["case_id"] == cid].iloc[0]
    
    print("="*60)
    print(f"CASE: {cid} | Pred Status: {p_row['deletion_status']} | Gold Status: {g_row['deletion_status']}")
    p_steps = json.loads(p_row["steps_json"])
    g_steps = json.loads(g_row["steps_json"])
    
    print("--- GOLD STEPS ---")
    for s in g_steps:
        print(f"  {s.get('step_no')}. {s.get('phase')} | {s.get('system_id')} | {s.get('resource_id')} | {s.get('operation')} | {s.get('state')} | {s.get('evidence_id')}")
    print("--- PRED STEPS ---")
    for s in p_steps:
        print(f"  {s.get('step_no')}. {s.get('phase')} | {s.get('system_id')} | {s.get('resource_id')} | {s.get('operation')} | {s.get('state')} | {s.get('evidence_id')}")
