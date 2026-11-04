import json
import sys
sys.path.insert(0, '.')
from code.retriever import EvidenceRetriever
from code.investigator import DeletionInvestigator
import pandas as pd

df = pd.read_csv('dataset/sample_deletion_requests.csv')
case12_row = df[df['case_id'] == 'case_12'].iloc[0].to_dict()

retriever = EvidenceRetriever()
ctx = retriever.retrieve_context(case12_row)

print("Profile:", ctx.user_profile)
print("Activities count:", len(ctx.relevant_activities))
print("Evidence count:", len(ctx.relevant_evidence))
print("Associated resources:", ctx.associated_resources)

for ev in ctx.relevant_evidence:
    print("EV:", ev["file_id"], len(ev.get("records", [])))
    for r in ev.get("records", [])[:5]:
        print("  Record:", r)

investigator = DeletionInvestigator()
status, steps = investigator.investigate(ctx)
print("PREDICTED STATUS:", status)
print("PREDICTED STEPS:", json.dumps(steps, indent=2))
