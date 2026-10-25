"""Extract the knowledge base hard-coded in the original CuSTaRD prototype.

Sources (original prototype):
  apps/home/views.py      register_asset.risk_mapping  -> category vulnerabilities, likelihood, primary treatment
  apps/home/views.py      asset_dependency if/elif     -> dependency vulnerabilities and 3 treatments each
  apps/templates/home/settings.html  checklistOptions  -> type -> category -> 10 checklist items
"""
import ast
import json
import re
import sys
from pathlib import Path

src = Path(sys.argv[1])
views = (src / "apps/home/views.py").read_text()
tree = ast.parse(views)

# 1. risk_mapping dict literal
risk_mapping = None
for node in ast.walk(tree):
    if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "risk_mapping" for t in node.targets):
        risk_mapping = ast.literal_eval(node.value)
assert risk_mapping, "risk_mapping not found"

# 2. asset_dependency if/elif chains
def chain(if_node):
    while isinstance(if_node, ast.If):
        yield if_node
        if len(if_node.orelse) == 1 and isinstance(if_node.orelse[0], ast.If):
            if_node = if_node.orelse[0]
        else:
            break

dep_func = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "asset_dependency")
dep_vulns, dep_treatments = {}, {}
for node in ast.walk(dep_func):
    if isinstance(node, ast.If) and isinstance(node.test, ast.Compare):
        left = node.test.left
        if isinstance(left, ast.Attribute) and left.attr == "category":  # asset.category == 'X'
            for br in chain(node):
                cat = br.test.comparators[0].value
                if cat in dep_vulns:
                    continue
                dep_vulns[cat] = [c.value.args[0].value for c in br.body
                                  if isinstance(c, ast.Expr) and isinstance(c.value, ast.Call)]
        elif isinstance(left, ast.Name) and left.id == "category":   # category == 'V'
            for br in chain(node):
                v = br.test.comparators[0].value
                lst = ast.literal_eval(br.body[0].value)
                dep_treatments.setdefault(v, lst)  # first definition wins (Python if/elif semantics)

# 3. checklistOptions JS object
html = (src / "apps/templates/home/settings.html").read_text()
m = re.search(r"var checklistOptions = (\{.*?\n    \});", html, re.S)
js = m.group(1)
js = re.sub(r",\s*([}\]])", r"\1", js)           # trailing commas
js = js.replace('"', '\\"').replace("'", '"')       # single -> double quotes (no apostrophes in data)
checklists = json.loads(js)

json.dump({"risk_mapping": risk_mapping, "dep_vulns": dep_vulns, "dep_treatments": dep_treatments,
           "checklists": checklists}, sys.stdout, indent=1)
