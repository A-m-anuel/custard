# From dissertation to implementation

This document traces the requirements in *CuSTaRD – A Cyber Support Tool for Risk Decisions*
(MSc dissertation, University of Manchester, 2023) to the code in this repository.

## Functional requirements (dissertation 3.4.1)

| # | Requirement | Implementation |
|---|-------------|----------------|
| 1 | Asset management: register, categorise and maintain assets | `custard/inventory` (`Asset`, registration form, CSV import, archive/restore) |
| 2 | Risk assessment using the CIA triad | Asset CIA impact ratings and high-water mark (`Asset.impact`); NIST likelihood × impact (`custard/risk/engine.py`) |
| 3 | Scoring system from standards and hardening guides | `custard/inventory/scoring.py`, with checklists in `custard/catalog/data/catalog.json` |
| 4 | Vulnerability identification and mitigation strategies | Category risk mapping (`CategoryVulnerability`) applied by `custard/risk/services.sync_default_risks` |
| 5 | Dashboard view | `custard/reporting/views.dashboard`, `custard/reporting/metrics.py` |
| 6 | Reporting mechanism | PDF: `custard/reporting/pdf.py`; CSV exports: `custard/reporting/views.py` |
| 7 | Administrative controls with real-time tracking | Django admin (newest assets, exposure filter, report tracking with new and exposed assets), audit log |
| 8 | Standard integration (ISO/IEC 27001, NIST CSF) | NIST SP 800-30 risk method; `reference` fields on checklist items, vulnerabilities and mitigations for control mappings |

## NIST SP 800-30 steps (dissertation 2.1, Figure 1)

| Step | In CuSTaRD |
|------|------------|
| 1 System characterisation | Asset registration: type, category, owner, location, CIA impact |
| 2 Threat identification / 3 Vulnerability identification | Category default weaknesses from the knowledge base; manual risks for findings from pentests or scans |
| 4 Control analysis | CIA security checklist (assessment) and treatment status |
| 5 Likelihood determination | Likelihood per weakness (High/Medium/Low, NIST Table 3-4 definitions) |
| 6 Impact analysis | Confidentiality/integrity/availability impact per asset; high-water mark |
| 7 Risk determination | Likelihood × impact, NIST Table 3-6; level and action from Table 3-7 |
| 8 Control recommendations | Recommended mitigations per weakness and category, tracked as treatments |
| 9 Results documentation | PDF report, CSV exports, audit log |

## Dissertation test cases (Table 5)

| Test | Status | Automated test |
|------|--------|----------------|
| 1.1 Register asset with valid data | Pass | `tests/test_views.py::RegistrationViewTests.test_register_with_checklist` |
| 1.2 Duplicate asset name rejected | Pass (now case-insensitive) | `test_duplicate_name_rejected_case_insensitively` |
| 2.1 / 2.2 Category required | Pass | `test_category_required` |
| 3.1 / 3.2 Vulnerability mapping by category | Pass | `tests/test_workflow.py::RegistrationTests` |
| 4.x Asset list and treatments | Pass | `AccessControlTests`, `RegistrationTests` |
| 5.x Dependency visualisation | Pass | `tests/test_reports_graph.py::GraphTests` |
| **6 User adds a category** | **Failed in prototype, now passes** | `tests/test_views.py::CustomCategoryTests` |
| 7 Report model integrity | Pass | `tests/test_reports_graph.py::ReportTests` |
| 8 Asset model integrity | Pass | `tests/test_workflow.py` |

## Knowledge-base migration

The prototype hard-coded its knowledge in `views.py` (a `risk_mapping` dictionary and a 500-line
`if/elif` chain) and in a template (`checklistOptions`). The scripts in `tools/` parsed these sources and
normalised into `custard/catalog/data/catalog.json`:

- 3 asset types, 29 categories, 290 checklist items (10 per category).
- Pillars follow the prototype's rule: items 1–4 confidentiality, 5–7 integrity, 8–10 availability.
  They are now an explicit, editable field.
- 116 category→weakness mappings, each with the prototype's likelihood and category-specific mitigation.
- The dependency view's treatment library (3 mitigations per weakness) is attached as general
  mitigations, matched by exact name or a short hand-reviewed list of synonyms
  (e.g. "SQL Injections" / "SQL Injection").
- All 268 distinct mitigations from the prototype are preserved.

Organisations should review checklist pillars, likelihoods and mitigations against their own
standards; all of it is editable in the knowledge base and the admin site.
