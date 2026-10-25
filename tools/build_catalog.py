"""Normalise the prototype knowledge base into custard/catalog/data/catalog.json."""
import json
import sys

raw = json.load(open(sys.argv[1]))
rm, dep_v, dep_t, checklists = raw["risk_mapping"], raw["dep_vulns"], raw["dep_treatments"], raw["checklists"]

CATEGORY_ALIASES = {  # prototype spelling -> checklist (canonical) spelling
    "firewall": "Firewalls",
    "office productivity software": "Office Productivity Software (Microsoft Office)",
}
# Hand-reviewed equivalents: registration vulnerability name -> dependency-library name
SYNONYMS = {
    "Misconfigurations": "Misconfiguration", "Insecure Configurations": "Insecure Configuration",
    "SQL Injections": "SQL Injection", "Data Corruption": "Corruption of Data", "Data Leaks": "Data Leakage",
    "Weak Authentication": "Weak Authentication Mechanisms", "Physical Theft": "Physical Theft or Loss",
    "Theft": "Theft or Misappropriation", "Cloning": "Cloning and Skimming", "Tampering": "Physical Tampering",
    "Phishing Attacks": "Phishing Vulnerabilities", "Phishing Risks": "Phishing Vulnerabilities",
    "Corporate Espionage": "Industrial Espionage", "Accidental Leaks": "Accidental Disclosure",
    "Dependency Vulnerabilities": "Insecure Dependencies", "Weak Dependencies": "Insecure Dependencies",
    "Bypass Techniques": "Bypassing Mechanisms", "Bypass Attacks": "Bypassing Mechanisms",
    "Inadequate Scanning": "Inadequate Real-time Scanning", "Insecure Code": "Insecure Development Practices",
    "Unauthorized Sharing": "Unauthorized Distribution",
}

canonical = {c.lower(): c for cats in checklists.values() for c in cats}
def canon(cat):
    k = cat.lower()
    return canonical.get(k) or CATEGORY_ALIASES[k]

def split_top(s):
    """Split on commas that are not inside parentheses."""
    out, depth, cur = [], 0, ""
    for ch in s:
        depth += ch == "("
        depth -= ch == ")"
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    out.append(cur.strip())
    return [x for x in out if x]

library = {}   # vulnerability name -> {"mitigations": [..], "sources": set}
def add_vuln(name, mitigations, source):
    e = library.setdefault(name, {"mitigations": [], "sources": set()})
    for m in mitigations:
        if m.lower() not in (x.lower() for x in e["mitigations"]):
            e["mitigations"].append(m)
    e["sources"].add(source)

category_vulns = {}
for cat, v in rm.items():
    names, levels, treats = split_top(v["vulnerabilities"]), split_top(v["risk"]), split_top(v["risk_treatment"])
    assert len(names) == len(levels) == len(treats), (cat, names, levels, treats)
    c = canon(cat)
    category_vulns[c] = []
    for n, lvl, t in zip(names, levels, treats, strict=True):
        category_vulns[c].append({"name": n, "likelihood": lvl.upper(), "mitigations": [t]})
        add_vuln(n, [], "prototype:risk_mapping")
        dep_name = n if n in dep_t else SYNONYMS.get(n)
        if dep_name and dep_name in dep_t:
            add_vuln(n, dep_t[dep_name], f"prototype:dependency ({dep_name})")

used_dep = {SYNONYMS.get(n, n) for n in library}
for vulns in dep_v.values():
    for n in vulns:
        if n not in used_dep and n not in library:
            add_vuln(n, dep_t.get(n, []), "prototype:dependency")

types = []
for tname, cats in checklists.items():
    tcats = []
    for cname, items in cats.items():
        assert len(items) == 10, cname
        # Prototype rule (dissertation 3.4.4): items 1-4 confidentiality, 5-7 integrity, 8+ availability
        checklist = [{"text": it, "pillar": "C" if i < 4 else "I" if i < 7 else "A"} for i, it in enumerate(items)]
        tcats.append({"name": cname, "checklist": checklist, "vulnerabilities": category_vulns.get(cname, [])})
    types.append({"name": tname, "categories": tcats})

out = {
    "version": "1.0.0",
    "description": "CuSTaRD baseline knowledge base, migrated from the 2023 MSc prototype (University of "
                   "Manchester). Checklists derived from vendor hardening guidance; vulnerabilities and "
                   "mitigations from NIST SP 800-30, MITRE ATT&CK, OWASP, CVE and ISO/IEC 27001 as described "
                   "in the dissertation.",
    "asset_types": types,
    "vulnerabilities": [{"name": n, "mitigations": e["mitigations"], "source": "; ".join(sorted(e["sources"]))}
                        for n, e in sorted(library.items())],
}
missing = [c["name"] for t in types for c in t["categories"] if not c["vulnerabilities"]]
assert not missing, missing
json.dump(out, open(sys.argv[2], "w"), indent=1, ensure_ascii=False)
nm = sum(1 for n, e in library.items() if not e["mitigations"] and not any(
    v["name"] == n for vs in category_vulns.values() for v in vs))
cat_m = {m.lower() for vs in category_vulns.values() for v in vs for m in v["mitigations"]}
print(f"types={len(types)} categories={sum(len(t['categories']) for t in types)} "
      f"checklist_items={sum(len(c['checklist']) for t in types for c in t['categories'])} "
      f"library_vulns={len(library)} (no mitigation: {nm}) "
      f"distinct_mitigations={len(cat_m | {m.lower() for e in library.values() for m in e['mitigations']})}")
