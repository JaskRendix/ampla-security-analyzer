# **Developer Guide — Ampla Security Python Engine**

## 1. Project Structure
```
ampla_security/
├── cli/                 # CLI entry point
├── engine/              # Rule engine
│   ├── dispatcher.py
│   ├── registry.py
│   ├── context.py
│   └── rules/
├── normalization/       # Normalization pipeline
├── reporting/           # HTML output
├── xml/                 # XML utilities
├── utils/               # Helpers (hashing, ids, logging)
└── testing/             # Tests + golden validator
```

---

## 2. Adding Rules

### Rule Definition
```python
class MyCustomRule(Rule):
    match = "//Item[@type='SomeType']"
    category = "project"
    priority = 10

    def apply(self, context):
        findings = []
        for item in context.select(self.match):
            if self.check_condition(item):
                findings.append({
                    "severity": "warning",
                    "message": f"Issue in {item.get('name')}",
                    "item_id": item.get("id"),
                })
        return findings or None
```

### Registration
```python
registry.register_rule("project", MyCustomRule(), priority=10)
```

### Test
```python
context = EngineContext(tree, None)
assert MyCustomRule().apply(context)
```

---

## 3. Extending the Pipeline

### New Normalizer
```python
class CustomNormalizer:
    def normalize(self):
        root = etree.Element("Root")
        return etree.ElementTree(root)
```

### Integration
```python
normalizer = CustomNormalizer(tree)
output = normalizer.normalize()
```

### XML Utilities
```python
def custom_xpath_helper(el, pattern):
    return el.xpath(pattern)
```

---

## 4. Testing Strategy

### Unit Tests
```python
result = function_under_test(input)
assert result == expected
```

### Integration Tests
```python
project = normalize_project(xml)
security = extract_security(project)
authstore = normalize_authstore(xml)
assert verify_integrity(project, authstore)
```

### End‑to‑End
```python
results = run_pipeline(project_file, authstore_file)
assert results.has_findings
```

### Golden Files
```python
validator = GoldenValidator(".")
results = validator.validate_pipeline("p.xml", "a.xml")
assert results["comparisons"]["project_normalized"]["identical"]
```

---

## 5. Performance

- Context indexes:  
  - `items_by_id`  
  - `items_by_type`  
  - `properties_by_name`  
- Rule ordering:  
  1. Specific XPath  
  2. Priority  
  3. Declaration order  

---

## 6. Debugging

### Logging
```python
logger.setLevel(logging.DEBUG)
```

### XML Inspection
```python
print(etree.tostring(el, pretty_print=True).decode())
```

### Rule Debugging
```python
print(f"Applying {self.__class__.__name__}")
```

---

## 7. References
- **Security Pipeline**  
- **Normalization Reference**  
- **XSLT Stylesheets**  
