# Knowledge-base migration tools

These scripts produced `custard/catalog/data/catalog.json` from the 2023 prototype, where the
knowledge base was hard-coded in `apps/home/views.py` and `apps/templates/home/settings.html`.
They are kept for provenance and are not needed to run CuSTaRD.

```bash
python tools/extract_prototype_catalog.py /path/to/prototype/django_project > raw_catalog.json
python tools/build_catalog.py raw_catalog.json custard/catalog/data/catalog.json
```
