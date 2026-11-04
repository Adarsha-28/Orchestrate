import re
import os
import sys
import json
import pandas as pd

sys.path.insert(0, '.')

from code.evidence_loader import EvidenceLoader
from code.retriever import EvidenceRetriever, CaseContext, UserProfile
from code.investigator import DeletionInvestigator

# Let's inspect how the loader extracts evidence_03 right now
loader = EvidenceLoader()
ev3 = loader.extract_file("evidence_03")
print(f"evidence_03 records extracted: {len(ev3.get('records', []))}")
if ev3.get('records'):
    print("Sample record from evidence_03:", ev3['records'][0])
