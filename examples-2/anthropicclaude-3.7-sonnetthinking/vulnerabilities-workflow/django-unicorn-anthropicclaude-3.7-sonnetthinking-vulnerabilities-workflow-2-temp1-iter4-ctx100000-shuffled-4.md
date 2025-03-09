# VULNERABILITIES

## 1. Arbitrary Method Execution via AJAX

**Description**: Django-Unicorn allows calling any public method on components via AJAX requests without explicit restrictions. The system checks if the method exists on the component but doesn't verify if it's intended to be called from the client side. This allows attackers to call any public method on a component, even those that were not meant to be exposed to users.

**Impact**: High - An attacker can execute arbitrary public methods on components, potentially leading to unauthorized actions such as data manipulation, privilege escalation, or information disclosure depending on what methods are available.

**Vulnerability rank**: High

**Currently implemented mitigations**: Django-Unicorn requires a valid CSRF token with each request to prevent cross-site request forgery. Components must be explicitly created by developers.

**Missing mitigations**: No whitelist mechanism for client-callable methods. No decorator or naming convention to mark which methods can be called from the client.

**Preconditions**: The attacker must be able to interact with a page that uses Django-Unicorn components, either as a legitimate user or by getting a victim to click on a crafted link.

**Source code analysis**:
In `django_unicorn/views/action_parsers/call_method.py`, the method execution is handled without restrictions:
```python
def _call_method_name(component: UnicornView, method_name: str, args: Tuple[Any], kwargs: Dict[str, Any]) -> Any:
    # ...
    if method_name is not None and hasattr(component, method_name):
        func = getattr(component, method_name)
        # ... argument processing ...
        if parsed_args:
            return func(*parsed_args, **parsed_kwargs)
        elif parsed_kwargs:
            return func(**parsed_kwargs)
        else:
            return func()
```
There's no check to verify if the method should be exposed to client-side calls. Any public method on the component can be called.

Looking at `django_unicorn/call_method_parser.py`, we can see how method names with arguments are parsed from strings sent by the client:
```python
@lru_cache(maxsize=128, typed=True)
def parse_call_method_name(
    call_method_name: str,
) -> Tuple[str, Tuple[Any, ...], Mapping[str, Any]]:
    """
    Parses the method name from the request payload into a set of parameters to pass to
    a method.
    """
```
This allows an attacker to call any method with arbitrary arguments.

**Security test case**:
1. Create a Django project with Django-Unicorn installed
2. Create a component with an unintended public method that performs sensitive actions:
```python
class SensitiveComponent(UnicornView):
    user_role = "user"

    def escalate_privileges(self):
        # This method is not intended to be called from the frontend
        self.user_role = "admin"
```
3. Create a malicious script that calls this method directly via AJAX:
```javascript
fetch('/unicorn/message/sensitive-component', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value
  },
  body: JSON.stringify({
    actionQueue: [{ type: 'callMethod', payload: { name: 'escalate_privileges' } }],
    data: {},
    checksum: 'valid-checksum', // This would be calculated based on the data
    id: 'component-id',
    epoch: Date.now()
  })
})
```
4. Verify that the method is called successfully and privileges are escalated

## 2. Cross-Site Scripting (XSS) via Safe Content Rendering

**Description**: Django-Unicorn provides a `safe` feature in component Meta classes that allows fields to be rendered without HTML encoding. This can lead to XSS vulnerabilities if used with untrusted content. Additionally, the library has a `sanitize_html` function that escapes HTML special characters but then marks the result as safe, which could be problematic if used incorrectly.

**Impact**: High - Could allow attackers to execute arbitrary JavaScript in users' browsers, leading to cookie theft, session hijacking, or other client-side attacks.

**Vulnerability rank**: High

**Currently implemented mitigations**: By default, content is HTML encoded before being sent to clients.

**Missing mitigations**: No strict Content Security Policy (CSP) recommendations. Insufficient warnings about the dangers of the `safe` feature with user-supplied content.

**Preconditions**: A component must use the `safe` feature with content that could be controlled by an attacker.

**Source code analysis**:
From `django_unicorn/views/__init__.py`, we can see the safe feature implementation:
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

This code marks fields as safe, which means they won't be HTML encoded before being sent to clients.

From `django_unicorn/utils.py`:
```python
def sanitize_html(html: str) -> SafeText:
    html = html.translate(_json_script_escapes)
    return mark_safe(html)  # noqa: S308
```
This function escapes HTML special characters but marks the result as safe, which could lead to XSS if used inappropriately.

The XSS vulnerability through `safe` fields is clearly demonstrated in `tests/views/test_process_component_request.py`:
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

**Security test case**:
1. Create a Django project with Django-Unicorn installed
2. Create a component that allows user input and marks it as safe:
```python
class XssVulnerableComponent(UnicornView):
    user_input = "<script>alert(document.cookie)</script>"

    class Meta:
        safe = ("user_input",)
```
3. Create a template that renders this component:
```html
<div>
    {% unicorn 'xss-vulnerable' %}
</div>
```
4. Visit the page and verify that the JavaScript executes, demonstrating the XSS vulnerability
