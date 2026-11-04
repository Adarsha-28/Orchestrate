import re
import os
import sys
import json
import pandas as pd

sys.path.insert(0, '.')

# Test improved parsing and investigation
from code.retriever import EvidenceRetriever
from code.investigator import DeletionInvestigator

r = EvidenceRetriever()
df_sample = pd.read_csv('dataset/sample_deletion_requests.csv')
df_gold = pd.read_csv('dataset/sample_output.csv')

print("Loaded retriever and datasets.")
