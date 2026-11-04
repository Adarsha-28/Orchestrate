import re

def matches_token(token: str, text: str) -> bool:
    if not token or len(token) < 3:
        return False
    # If token starts with user_ or account_ or has digits, require word boundary
    pattern = r'(?<![a-zA-Z0-9_])' + re.escape(token) + r'(?![a-zA-Z0-9_])'
    return bool(re.search(pattern, text, re.IGNORECASE))

print("user_28 in user_280:", matches_token("user_28", "user_280"))
print("user_28 in user_28:", matches_token("user_28", "user_28"))
print("user_28 in {'sub': 'user_28'}:", matches_token("user_28", "{'sub': 'user_28'}"))
