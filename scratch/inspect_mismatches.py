import pandas as pd
import json

df_pred = pd.read_csv('scratch/sample_run_output.csv')
df_gold = pd.read_csv('dataset/sample_output.csv')
df_req = pd.read_csv('dataset/sample_deletion_requests.csv')

merged = pd.merge(df_pred, df_gold, on='case_id', suffixes=('_pred', '_gold'))
merged = pd.merge(merged, df_req, on='case_id')

mismatches = merged[merged['deletion_status_pred'] != merged['deletion_status_gold']]
print(f"Total status mismatches: {len(mismatches)}")
for _, r in mismatches.iterrows():
    print('='*60)
    print(f"{r['case_id']}: Pred={r['deletion_status_pred']} vs Gold={r['deletion_status_gold']}")
    print(f"Request: {r['request_text']}")
    print(f"Requested At: {r['requested_at']} -- Audit At: {r['audit_at']}")
    print(f"Reported status: {r['reported_status']}")
    print(f"Pred Steps ({len(json.loads(r['steps_json_pred']))}):")
    for s in json.loads(r['steps_json_pred']):
        print('  P:', s)
    print(f"Gold Steps ({len(json.loads(r['steps_json_gold']))}):")
    for s in json.loads(r['steps_json_gold']):
        print('  G:', s)
