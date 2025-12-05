import os
import json
import re
from difflib import SequenceMatcher

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

# durante il retrieve si controllano le entità già estrapolate da un ipotetico LDAP
def parse_entities_file(path):
    sections = {"subjects": [], "actions": [], "resources": [], "purposes": [], "conditions": []}
    cur = None
    if not os.path.exists(path):
        return sections
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"\[(.+)\]", line.lower())
            if m:
                key = m.group(1).strip()
                cur = key if key in sections else None
                continue
            if cur:
                sections[cur].append(line)
    return sections

def read_entities(environment):
    filename = f"{environment}.txt"
    path = os.path.join(DATA_DIR, filename)
    return parse_entities_file(path)


def norm(s):
    return re.sub(r"\s+", " ", (s or "").strip().lower())

# similarità tra stringhe 0-1
def ratio(a, b):
    return SequenceMatcher(None, norm(a), norm(b)).ratio()

# similarità del coseno 5k
def rank_entities(query, items, k=5):
    scored = sorted([(it, ratio(query, it)) for it in items], key=lambda x: x[1], reverse=True)
    return [t for t, _ in scored[:max(1, k)]]

#  nearest
def nearest(value, vocab, threshold=0.6):
    if not value or not vocab:
        return "none"
    best = None
    best_r = 0.0
    for it in vocab:
        r = ratio(value, it)
        if r > best_r:
            best_r, best = r, it
    return best if best and best_r >= threshold else "none"

# Step 4 
def ensure_policy_parameters(policy_json, environment, vocab=None):
    if vocab and isinstance(vocab, dict):
        entities = {
            "subjects": vocab.get("subjects", []),
            "actions": vocab.get("actions", []),
            "resources": vocab.get("resources", []),
            "purposes": vocab.get("purposes", []),
            "conditions": vocab.get("conditions", []),
        }
    else:
        entities = read_entities(environment)

    #return nearest
    def snap(v, tipo):
        if v is None or v == "none":
            return "none"
        return nearest(str(v), entities.get(tipo, []))

    rules = []
    for r in policy_json.get("dsarcp", []):
        rules.append({
            "decision": r.get("decision", "deny") if r.get("decision") in ("allow", "deny") else "deny",
            "subject":   snap(r.get("subject"), "subjects"),
            "action":    snap(r.get("action"), "actions"),
            "resource":  snap(r.get("resource"), "resources"),
            "purpose":   snap(r.get("purpose"), "purposes"),
            "condition": snap(r.get("condition"), "conditions"),
        })
    return {"dsarcp": rules}

# Step 4 
def ensure_sar(policy_json, environment, vocab=None):
    if vocab and isinstance(vocab, dict):
        entities = {
            "subjects": vocab.get("subjects", []),
            "actions": vocab.get("actions", []),
            "resources": vocab.get("resources", []),
            "purposes": vocab.get("purposes", []),
            "conditions": vocab.get("conditions", []),
        }
    else:
        entities = read_entities(environment)

    #return nearest
    def snap(v, tipo):
        if v is None or v == "none":
            return "none"
        return nearest(str(v), entities.get(tipo, []))

    rules = []
    for r in policy_json.get("dsarcp", []):
        rules.append({
            "decision": r.get("decision", "deny") if r.get("decision") in ("allow", "deny") else "deny",
            "subject":   snap(r.get("subject"), "subjects"),
            "action":    snap(r.get("action"), "actions"),
            "resource":  snap(r.get("resource"), "resources"),
            "purpose":   r.get("purpose"),
            "condition": r.get("condition"),
        })
    return {"dsarcp": rules}