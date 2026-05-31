---
title: Reference
nav_order: 4
has_children: true
description: "Complete reference for ZeeKayDa.Auth endpoints, configuration, and public API"
permalink: /reference/
---

# Reference

The reference section is **information-oriented**. It provides precise, complete descriptions of
every public-facing endpoint, configuration option, and API type exposed by ZeeKayDa.Auth.

Reference material describes the library as it is — it does not teach or guide you through a task.
For step-by-step instructions, see the [How-to Guides](../how-to/). For background on design
decisions, see [Explanation](../explanation/).

---

## In this section

{% for page in site.pages %}
{% if page.parent == "Reference" %}
- [{{ page.title }}]({{ page.url | relative_url }})
{% endif %}
{% endfor %}
