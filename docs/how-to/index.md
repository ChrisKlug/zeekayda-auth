---
title: How-to Guides
nav_order: 3
has_children: true
description: "Task-focused guides for configuring and extending ZeeKayDa.Auth"
permalink: /how-to/
---

# How-to Guides

How-to guides are **task-oriented**. Each guide targets a specific goal and shows you the steps to
achieve it — assuming you already have a working ZeeKayDa.Auth setup.

If you are completely new and want a guided introduction, start with the [Tutorials](../tutorials/)
instead. If you want to understand *why* something works the way it does, read the
[Explanation](../explanation/) section.

---

## Available guides

{% for page in site.pages %}
{% if page.parent == "How-to Guides" %}
- [{{ page.title }}]({{ page.url | relative_url }})
{% endif %}
{% endfor %}
