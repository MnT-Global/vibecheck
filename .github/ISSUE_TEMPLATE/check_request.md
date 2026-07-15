---
name: New check request
about: Propose a new thing vibecheck should detect
title: ""
labels: check-request
---

**The failure mode**
What insecure / broken pattern should we catch? Ideally one that shows up in AI-generated
commerce code.

**Example**
A small code snippet that should be flagged, and one that should NOT be (the false-positive case).

**Category**
Secrets / Injection / Auth / Commerce-logic / Web / Performance / Production / Dependencies?

**Detectable without running the code?**
vibecheck is static analysis. Structural (a syntactic fact) or flow-dependent (needs data-flow)?
