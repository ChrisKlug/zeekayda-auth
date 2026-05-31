---
title: Explanation
nav_order: 5
has_children: true
description: "Concepts, design rationale, and background on how ZeeKayDa.Auth works"
permalink: /explanation/
---

# Explanation

The explanation section is **understanding-oriented**. It covers the concepts, design decisions, and
background context that help you use the library confidently.

Explanation documents answer *why* — why the library behaves the way it does, why the specs require
certain things, and why certain design trade-offs were made.

For actionable steps, see the [How-to Guides](../how-to/). For precise API details, see the
[Reference](../reference/).

---

## In this section

{% for page in site.pages %}
{% if page.parent == "Explanation" %}
- [{{ page.title }}]({{ page.url | relative_url }})
{% endif %}
{% endfor %}
