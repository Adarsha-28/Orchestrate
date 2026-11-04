import pandas as pd
import json
import sys
sys.path.insert(0, '.')
from code.retriever import EvidenceRetriever

r = EvidenceRetriever()
df_sample = pd.read_csv('dataset/sample_deletion_requests.csv')
df_gold = pd.read_csv('dataset/sample_output.csv')
row = df_sample[df_sample['case_id'] == 'case_11'].iloc[0].to_dict()
gold_row = df_gold[df_gold['case_id'] == 'case_11'].iloc[0]
ctx = r.retrieve_context(row)

print("CASE 11 Gold Status:", gold_row['deletion_status'])
print("Request text:", row['request_text'])
print("Gold steps:")
for s in json.loads(gold_row['steps_json']):
    print("  ", s)
print("Matched evidence files:", [e['file_id'] for e in ctx.relevant_evidence])
for e in ctx.relevant_evidence:
    print(" ", e['file_id'], e['matched_records'])
