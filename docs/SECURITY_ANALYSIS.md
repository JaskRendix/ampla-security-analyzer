# **Security Analysis Pipeline**

## 1. Pipeline Overview
Two phases:

1. **Normalization** — Convert project, document, and AuthStore XML into a consistent schema.  
2. **Security Analysis** — Apply XSLT rule templates to detect issues and generate HTML reports.

Pipeline is deterministic and template‑driven.

---

## 2. Architecture

### Directory Structure
```
StyleSheets/
  Project.Normalize.xslt
  Authstore.Normalize.xslt
  Project.Security.xslt
  Document.Security.xslt
  Document.Security.Text.xslt
External/css/security.css
AnalyseSecurity.cmd
```

Each XSLT corresponds to a pipeline stage.

---

## 3. Data Flow

```
Input XML
 → Normalize.xslt
     → Normalized XML
         → Security.xslt
             → HTML Report
```

Inputs:
- Project XML  
- AuthStore XML  
- Optional document XML/text  

Outputs:
- Project.Security.html  
- Document.Security.html  
- Authstore.Security.html  

---

## 4. Normalization

### XSLTs
- `Project.Normalize.xslt`  
- `Authstore.Normalize.xslt`

### Responsibilities
- Restructure XML  
- Remove irrelevant nodes  
- Compute metadata  
- Resolve references  
- Standardize naming  
- Inject defaults  
- Validate relationships  

### Template → Function Mapping
| XSLT Template | Role | Python Equivalent |
|---|---|---|
| `match="/Ampla"` | Project root | `normalize_project_ampla()` |
| `match="Item[@id]"` | Item normalization | `normalize_item()` |
| `name="addItemAttributes"` | Derived metadata | `add_item_attributes()` |
| `match="AzRole"` | Role normalization | `normalize_role()` |
| `name="lookupWellKnownSid"` | SID resolution | `lookup_well_known_sid()` |

This mapping defines Python function boundaries.

---

## 5. Security Analysis

### XSLTs
- `Project.Security.xslt`  
- `Document.Security.xslt`  
- `Document.Security.Text.xslt`

### Responsibilities
- Detect misconfigured permissions  
- Validate roles and scopes  
- Check broken references  
- Identify insecure XML constructs  
- Flag injection‑prone content  

Each `<xsl:template match="...">` is a rule.

### Python Rule Mapping
```python
def rule_missing_scope(node, ctx):
    if node.tag == "Scope" and not ctx.scope_exists(node):
        return HighRisk("Scope missing in project")
```

---

## 6. Command Script Behavior

`AnalyseSecurity.cmd` performs:

1. Apply normalization XSLT  
2. Apply security XSLT  
3. Write HTML output  

Two‑step transform:
```
Input → Normalize.xslt → Normalized → Security.xslt → HTML
```

---

## 7. Python Migration Plan

### Phase 1 — Infrastructure
- Package layout  
- CLI  
- XML engine (`lxml`)  

### Phase 2 — Template Dispatcher
- Match rules  
- Precedence  
- Context indexing  

### Phase 3 — Port Normalization XSLTs
- Template → function  
- Named templates → helpers  
- Match patterns → dispatch rules  

### Phase 4 — Port Security XSLTs
- Template → rule  
- Output blocks → HTML generator  

### Phase 5 — Pipeline Orchestration
- Replace `.cmd` script  
- Logging and error handling  

### Phase 6 — Testing
- Compare Python output to XSLT output  
- Golden‑file regression suite  
