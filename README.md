# **Ampla Security Python Engine**

A Python implementation of the Ampla security‑analysis pipeline.  
This engine replaces the original XSLT system with a modular and testable architecture.

**Original XSLT implementation:**  
[https://github.com/Ampla/SecurityAnalysis](https://github.com/Ampla/SecurityAnalysis)

---

## **Features**

### **Normalization Pipeline**
- Project structure normalization  
- Metadata extraction  
- Hash computation  
- Property filtering  
- Type and reference processing  
- Class definition handling  
- Expression parsing  
- AuthStore normalization  
- User, role, and scope mapping  
- Specialized transforms:
  - CycleManager cycles  
  - Resolver defaults  
  - Historical expression annotation  
  - Home and Favorites counters  

### **Security Analysis**
- Rule engine  
- XPath‑style pattern matching  
- Context indexing  
- Permission and scope validation  
- HTML reporting  

### **Tooling**
- CLI interface  
- Python API  
- Golden‑file validation  
- Functional and integration tests  
- Full documentation  

---

## **Installation**

### **Requirements**
- Python **3.10+**  
- `lxml`  

### **Install**

```bash
git clone <repository>
cd SecurityAnalysis-master

python3 -m venv .venv
source .venv/bin/activate

pip install .
```

For development:

```bash
pip install .[dev]
```

---

## **CLI Usage**

```bash
python -m ampla_security.cli.analyze \
  --project AmplaProject.xml \
  --authstore AuthStore.xml \
  --output security_report.html
```

### **Options**

```
--help
--normalize-only
--verbose
```

---

## **Python API**

```python
from lxml import etree
from ampla_security.normalization.project_normalizer import ProjectNormalizer

tree = etree.parse("AmplaProject.xml")
normalizer = ProjectNormalizer(tree)
normalized = normalizer.normalize()

users = normalized.getroot().xpath("//Item[@type='Citect.Ampla.StandardItems.User']")
print(len(users))
```

---

## **Testing**

```bash
pytest -v
pytest --cov=ampla_security
```

Golden‑file validation:

```bash
python -c "from ampla_security.testing.golden_validator import GoldenValidator; \
           GoldenValidator('.').validate_pipeline('synthetic_project.xml', 'synthetic_authstore.xml')"
```

---

## **Architecture**

- Modular pipeline: normalization → extraction → analysis → reporting  
- Rule engine replaces XSLT templates  
- Deterministic hashing  
- Structured error handling  
- Version‑aware defaults  

---

## **Compatibility**

- Python **3.10+**  
- lxml 4.6+  
- Linux, macOS, Windows  

---

## **Documentation**

- `docs/SECURITY_ANALYSIS.md`  
- `docs/SECURITY_PIPELINE.md`  
- `docs/NORMALIZATION_REFERENCE.md`  
- `docs/DEVELOPER_GUIDE.md`  
- `docs/VALIDATION_REPORT.md`  

---

## **Roadmap**

- Extended rule library  
- REST API  
- Database backend  
- Multi‑project analysis  
- Performance improvements  
