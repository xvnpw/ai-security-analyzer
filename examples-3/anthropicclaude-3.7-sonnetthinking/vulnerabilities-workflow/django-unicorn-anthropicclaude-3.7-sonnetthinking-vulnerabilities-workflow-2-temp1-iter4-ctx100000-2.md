# VULNERABILITIES

## 1. Cross-Site Scripting (XSS) via Meta.safe Attribute

### Description
Django Unicorn provides developers the ability to mark fields as "safe" (unescaped) using the `Meta.safe` attribute. If a developer marks a field as safe and that field contains user-controlled content, it creates a dangerous XSS vulnerability. By default, Django Unicorn HTML-encodes field values to prevent XSS attacks, but when a field is explicitly added to the `Meta.safe` tuple, this protection is bypassed, allowing raw HTML to be rendered.

### Impact
High. If exploited, an attacker could execute arbitrary JavaScript in the context of the victim's browser, potentially leading to session hijacking, data theft, or complete account takeover. This is especially dangerous in applications handling sensitive data or authentication.

### Vulnerability rank
High

### Currently implemented mitigations
The framework escapes HTML by default to prevent XSS. Developers must explicitly opt out of this protection by adding fields to the `Meta.safe` tuple. The documentation does mention that this is specifically for preventing XSS attacks.

### Missing mitigations
- The framework could provide more prominent warnings about the risks of using `Meta.safe`
- Additional runtime checks could be implemented to detect when user-controlled input is marked as safe
- A content security policy header could be recommended or automatically implemented

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

This code explicitly looks for fields marked as "safe" in the Meta class and applies Django's `mark_safe` function to them, which bypasses HTML escaping.

The test in `tests/views/test_process_component_request.py` demonstrates this vulnerability:
```python
def test_safe_html_entities_not_encoded(client):
    data = {"hello": "test"}
    action_queue = [
        {
            "payload": {"name": "hello", "value": "<b>test1</b>"},
            "type": "syncInput",
        }
    ]
    response = post_and_get_response(
        client,
        url="/message/tests.views.test_process_component_request.FakeComponentSafe",
        data=data,
        action_queue=action_queue,
    )

    assert not response["errors"]
    assert response["data"].get("hello") == "<b>test1</b>"
    assert "<b>test1</b>" in response["dom"]
```

This test shows that when a field is marked as "safe" using the `Meta.safe` attribute, HTML is not encoded when rendered, potentially allowing XSS attacks.

### Security test case
1. Create a component with a text input field that accepts user input:
```python
class VulnerableView(UnicornView):
    user_input = ""

    class Meta:
        safe = ("user_input",)
```

2. Create a template that displays this field:
```html
<div>
  <input unicorn:model="user_input" type="text" />
  <div>{{ user_input }}</div>
</div>
```

3. Enter a malicious payload such as `<img src="x" onerror="alert(document.cookie)">` into the input field

4. Verify that the JavaScript executes when the component updates, demonstrating the XSS vulnerability
