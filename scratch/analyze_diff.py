import pandas as pd
import json

df_pred = pd.read_csv('scratch/sample_run_output.csv')
df_gold = pd.read_csv('dataset/sample_output.csv')

merged = pd.merge(df_pred, df_gold, on='case_id', suffixes=('_pred', '_gold'))

print('=== STATUS MISMATCHES ===')
for _, r in merged.iterrows():
    if r['deletion_status_pred'] != r['deletion_status_gold']:
        print(f"{r['case_id']}: Pred={r['deletion_status_pred']}, Gold={r['deletion_status_gold']}")
        print(f"  Pred steps: {len(json.loads(r['steps_json_pred']))}, Gold steps: {len(json.loads(r['steps_json_gold']))}")

print('\n=== STEP MISMATCHES (ON MATCHING STATUS) ===')
for _, r in merged.iterrows():
    if r['deletion_status_pred'] == r['deletion_status_gold']:
        p_steps = json.loads(r['steps_json_pred'])
        g_steps = json.loads(r['steps_json_gold'])
        if p_steps != g_steps:
            print(f"\n{r['case_id']} ({r['deletion_status_pred']}): Pred={len(p_steps)} steps, Gold={len(g_steps)} steps")
            p_keys = [(s['phase'], s['operation'], s['system_id'], s['resource_id'], s['evidence_id']) for s in p_steps]
            g_keys = [(s['phase'], s['operation'], s['system_id'], s['resource_id'], s['evidence_id']) for s in g_steps]
            
            p_set = set(p_keys)
            g_set = set(g_keys)
            
            missing_in_pred = g_set - p_set
            extra_in_pred = p_set - g_set
            if missing_in_pred:
                print("  Missing in Pred:", list(missing_in_pred)[:3])
            if extra_in_pred:
                print("  Extra in Pred:", list(extra_in_pred)[:3])
