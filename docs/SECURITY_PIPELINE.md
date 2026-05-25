# **Security Pipeline Guide**

## Pipeline
```
Project XML
 → Project Normalization
 → Security Extraction
 → AuthStore Normalization
 → Rule Application
 → HTML Report
```

---

## Phase 1 — Project Normalization  
**Module:** `normalization/project_normalizer.py`

**Functions**
- Normalize project root, references, types, items, properties  
- Compute: `hash`, `fullName`, `DisplayOrder`  
- Apply transforms:
  - normalize_cycle_manager_cycles  
  - normalize_resolver_item  
  - normalize_historical_field_expression  
  - normalize_home_property  
  - normalize_favorites_property  

**Excluded properties**
- RunState  
- DisplayOrderIndex  
- DisplayOrderGroup  
- PropertyMaskSets  
- DataSource  
- Definition  

---

## Phase 2 — Security Extraction  
**Module:** `normalization/project_security_extractor.py`

**Extracts**
- Users  
- Scopes  
- Identity/SID data  
- SecurityID values  

---

## Phase 3 — AuthStore Normalization  
**Module:** `normalization/authstore_normalizer.py`

**Functions**
- Normalize AzAdminManager  
- Normalize operations, roles, scopes, tasks  
- Resolve accounts (Windows, Ampla, well‑known SIDs)  
- Link AuthStore data to project security data  

---

## Phase 4 — Rule Application  
**Module:** `engine/`

**Categories**
- Authorization  
- Project  
- Common  
- Document  

**Dispatcher**
- Priority‑based  
- Pattern‑based  
- Ordered execution  

---

## Phase 5 — HTML Report  
**Module:** `reporting/html_reporter.py`

**Contents**
- Findings summary  
- Roles  
- Scopes  
- Permissions  
- User status  

---

## CLI
```
python -m ampla_security.cli.analyze \
  --project project.xml \
  --authstore authstore.xml \
  --output report.html
```

Options: `--normalize-only`, `--verbose`, `--help`

---

## Integration

**Dispatcher**
```python
dispatcher.run("authorization")
```

**Context**
```python
context.get_items_by_type("User")
```

**Registry**
```python
registry.register_rule(category, rule, priority)
```

---

## Outputs
- Normalized project XML  
- Normalized AuthStore XML  
- Extracted security data  
- HTML report  

---

## Tests
- Functional tests: `testing/test_functional.py`  
- Golden‑file tests: `testing/golden_validator.py`  

Commands:
```
pytest -v
pytest --cov=ampla_security
python ampla_security/testing/golden_validator.py
```

---

## Performance
- Full pipeline < 1s  

---

## Differences from XSLT
- SHA1 hashing  
- Version‑based DisplayOrder  
- Different intermediate formats  
- More detailed errors  
- Extensible architecture  

---

## Future Work
- More rules  
- Plugin system  
- Parallel rule execution  
- Database integration  
- REST API  
