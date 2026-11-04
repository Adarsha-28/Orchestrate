import sys
sys.path.insert(0, '.')
from code.evaluation.main import evaluate_predictions
import json

res = evaluate_predictions("scratch/sample_run_output.csv", "dataset/sample_output.csv")
print(f"Status accuracy: {res['status_accuracy']*100:.1f}% ({res['correct_status']}/{res['total_cases']})")
print(f"Sequence accuracy: {res['sequence_accuracy']*100:.1f}% ({res['exact_seq_matches']}/{res['total_cases']})")

for d in res['case_diffs']:
    print(f"Case {d['case_id']}: pred={d['status_pred']} gold={d['status_gold']} (steps pred={d['steps_pred_count']} gold={d['steps_gold_count']})")
