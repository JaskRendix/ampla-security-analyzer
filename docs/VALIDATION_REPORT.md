# Golden‑File Validation Report

## Summary
Python and XSLT pipelines both execute.  
Architectures differ.  
Core logic works, but structural mismatches prevent golden‑file parity.

---

## Architecture Differences
- Python uses an **AuthStore** intermediate model; XSLT outputs **Security** directly.  
- Python injects security data via methods; XSLT uses parameters.  
- Python hashes IDs with **SHA1**; XSLT uses **generate-id()**.  
- Python applies version‑based defaults; XSLT uses static values.

These are design divergences, not regressions.

---

## Findings

### 1. Project Normalized XML
**Status:** Differences, not defects.

- Hash values differ (SHA1 vs. generate-id).  
- DisplayOrder differs (50000 vs. 0).  
- Formatting differences.

**Impact:** Low. Structure and semantics match.

---

### 2. AuthStore Normalized XML
**Status:** Structural mismatch.

Python:
```
<AuthStore>
  <AuthorizationApplication>…</AuthorizationApplication>
</AuthStore>
```

XSLT:
```
<Security>
  <Operations/>
  <RoleDefinitions/>
  <Scopes/>
  <Users/>
</Security>
```

Python produces an internal representation; XSLT produces the final schema.

**Impact:** Critical. Parity impossible until Python emits the XSLT schema.

---

### 3. HTML Security Report
**Status:** Not comparable.

HTML differences stem from the mismatched XML input.  
Blocked until AuthStore output matches XSLT’s Security format.

---

## Required Actions

### Priority 1
- Decide whether Python should:
  - **Output Security XML directly**, or
  - **Add a SecurityTransformer** to convert AuthStore → Security.

This is the blocker for golden‑file parity.

### Priority 2
- Align or document hash algorithm differences.  
- Align or document DisplayOrder logic.  
- Add regression tests with explicit “expected differences.”

---

## Next Steps
1. Confirm intended Python output format.  
2. Implement Security output path.  
3. Re‑run golden‑file validation.  
4. Update test suite and documentation.
